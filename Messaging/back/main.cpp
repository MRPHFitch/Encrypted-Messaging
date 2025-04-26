/**
 * @file Messaging
 * @author Matthew Fitch
 * @version 1.0
 * @date 2025-04-16
 * Description: Functions for both Client and Server side of things. Initializes communication, uses crypto.cpp
 * to actually negotiate key, encrypt then send message, and decrypt then display message.
 * 
*/
#include <iostream>
#include <cstdio>
#include <string>
#include <vector>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include "crypto.hpp"

using namespace std;

void printHex(const vector<unsigned char>& data) {
    for (unsigned char byte : data) {
        printf("%02x", byte);
    }
    printf("\n");
}

void initializeOpenssl(){
    SSL_load_error_strings();
    OpenSSL_add_ssl_algorithms();
}

void cleanupOpenssl(){
    EVP_cleanup();
}

SSL_CTX* createContext(bool isServer){
    const SSL_METHOD* method;
    SSL_CTX* ctx;
    //Establish context for either server or client
    if(isServer){
        method=SSLv23_server_method();
    }
    else{
        method=SSLv23_client_method();
    }
    ctx=SSL_CTX_new(method);
    if(!ctx){
        perror("Unable to create SSL context.");
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }
    return ctx;
}

void configureContext(SSL_CTX* ctx, bool isServer){
    if(isServer){
        //Set cert and private key for the server
        if(SSL_CTX_use_certificate_file(ctx, "server.crt", SSL_FILETYPE_PEM) <=0){
            ERR_print_errors_fp(stderr);
            exit(EXIT_FAILURE);
        }
        if(SSL_CTX_use_PrivateKey_file(ctx, "server.key", SSL_FILETYPE_PEM) <= 0){
            ERR_print_errors_fp(stderr);
            exit(EXIT_FAILURE);
        }
    }
}
int main() {
    // Initialize OpenSSL
    initializeOpenssl();

    //Create SSL context for the server
    SSL_CTX* ctx=createContext(true);
    configureContext(ctx, true);

    //Create the socket
    int serveSock=socket(AF_INET, SOCK_STREAM, 0);
    struct sockaddr_in addr;
    addr.sin_family=AF_INET;
    addr.sin_port=htons(49250);
    addr.sin_addr.s_addr=htonl(INADDR_ANY);

    bind(serveSock, (struct sockaddr*)&addr, sizeof(addr));
    listen(serveSock, 1);

    cout<<"Listening on port 49250..."<<endl;

    while(1){
        //wrap socket in encryption
        struct sockaddr_in addr;
        uint len=sizeof(addr);
        SSL* ssl;
        int cSock=accept(serveSock, (struct sockaddr*)&addr, &len);
        ssl=SSL_new(ctx);
        SSL_set_fd(ssl, cSock);

        if(SSL_accept(ssl) <= 0){
            ERR_print_errors_fp(stderr);
        }
        else{
            // Step 1: Generate Diffie-Hellman parameters (shared settings)
            cout << "Generating Diffie-Hellman parameters...\n";
            DH *dh = cryptography::generate_dh_params();

            // Step 2: Generate DH public key
            BIGNUM *pubKeyBn = BN_new();
            DH_get0_key(dh, &pubKeyBn, nullptr);

            // Step 3: Convert public key to bytes
            vector<unsigned char> pubKeyBytes(DH_size(dh));
            int len = BN_bn2bin(pubKeyBn, pubKeyBytes.data());
            pubKeyBytes.resize(len);

            //Print for debug
            cout << "My public key (hex): ";
            printHex(pubKeyBytes);

            // Step 4: Send public key to peer (simulated in this example)
            SSL_write(ssl, pubKeyBytes.data(), pubKeyBytes.size());

            // Step 5: Assume we receive the peer's public key (simulated here)
            unsigned char peerKeyBytes[256];
            int peerKeyLen=SSL_read(ssl, peerKeyBytes, sizeof(peerKeyBytes));

            vector<unsigned char> peerKey(peerKeyBytes, peerKeyBytes+peerKeyLen);

            // Step 6: Generate shared secret using peer's public key
            cout << "Generating shared secret...\n";
            vector<unsigned char> sharedKey = cryptography::generate_shared_secret(dh, peerKey);

            //Print for debug
            cout << "Shared secret (hex): ";
            printHex(sharedKey);

            // Step 7: Generate AES key from the shared secret
            vector<unsigned char> sessionKey(sharedKey.begin(), sharedKey.begin() + 32); // AES-256 requires 32 bytes

            //Print for debug
            cout << "AES key (hex): ";
            printHex(sessionKey);

            // Step 8: Encrypt a message
            string message = "Hello, Peer! This is a secret message.";
            vector<unsigned char> encMessage = cryptography::aes_encrypt(
                vector<unsigned char>(message.begin(), message.end()), sessionKey);

            //Print for debug
            cout << "Encrypted message (hex): ";
            printHex(encMessage);

            // Step 9: Send Message
            SSL_write(ssl, encMessage.data(), encMessage.size());

            // Step 10: Decrypt the message on the receiving side (same peer)
            vector<unsigned char> decMessage = cryptography::aes_decrypt(encMessage, sessionKey);

            cout << "Decrypted message: ";
            string decrypted_str(decMessage.begin(), decMessage.end());
            cout << decrypted_str << endl;

            // Clean up OpenSSL
            DH_free(dh);
        }
        SSL_shutdown(ssl);
        SSL_free(ssl);
        close(cSock);
    }
    close(serveSock);
    SSL_CTX_free(ctx);
    cleanupOpenssl();

    return 0;
}