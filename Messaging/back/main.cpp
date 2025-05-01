/**
 * @file Messaging
 * @author Matthew Fitch
 * @version 2.0
 * @date 2025-04-16
 * @details: Functions for both Client and Server side of things. Sets up a KDC, sockets, and TLS. Wraps the sockets in TLS for secure communication,
 * encrypts necessary keys before placing into KDC, and retrieves all information of users involved and establishes a chat. Once session established, 
 * retrieves message from front end, encrypts the message, and sends it to the peer. Peer then decrypts message, and has it sent to front end to display. 
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
#include <unordered_map>
#include <mutex>
#include "crypto.hpp"

using namespace std;

struct KeyInfo{
    string name;
    string id;
    KeyPair idKey;
    KeyPair signedKey;
    vector<unsigned char>signedPreSig;
    vector<KeyPair>oneTimeKeys;
};

class KDC{
    private:
        unordered_map<string, KeyInfo>keyMap;
        mutex mapMutex;
    public:
        void addKey(const KeyInfo& info){
            lock_guard<mutex> lock(mapMutex);
            keyMap[info.id]=info;
        }
        KeyInfo getKey(const string& ID){
            lock_guard<mutex> lock(mapMutex);
            if(keyMap.find(ID) != keyMap.end()){
                return keyMap[ID];
            }
            else{
                throw runtime_error("Key not found.");
            }
        }
        void removeKey(const string& ID){
            lock_guard<mutex> lock(mapMutex);
            keyMap.erase(ID);
        }
};
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
    //Initialize KDC
    KDC control;

    // Initialize OpenSSL
    initializeOpenssl();
    cryptography::initialize();

    //Create SSL context for the server
    SSL_CTX* ctx=createContext(true);
    configureContext(ctx, true);

    //Create the socket
    int serveSock=socket(AF_INET, SOCK_STREAM, 0);
    struct sockaddr_in addr;
    addr.sin_family=AF_INET;
    addr.sin_port=htons(49250);
    addr.sin_addr.s_addr=htonl(INADDR_ANY);

    if(::bind(serveSock, (struct sockaddr*)&addr, sizeof(addr))<0){
        perror("Unable to bind.");
        exit(EXIT_FAILURE);
    }
    if(listen(serveSock, 1)<0){
        perror("Unable to listen.");
        exit(EXIT_FAILURE);
    }

    cout<<"Listening on port 49250..."<<endl;

    while(1){
        //wrap socket in encryption
        struct sockaddr_in clientAddr;
        socklen_t len=sizeof(clientAddr);
        SSL* ssl;
        int cSock=accept(serveSock, (struct sockaddr*)&addr, &len);
        if(cSock<0){
            perror("Unable to accept.");
            continue;
        }
        ssl=SSL_new(ctx);
        SSL_set_fd(ssl, cSock);

        if(SSL_accept(ssl) <= 0){
            ERR_print_errors_fp(stderr);
        }
        else{
            //Retrieve Client's info
            string peerAddress=inet_ntoa(clientAddr.sin_addr);

            //Placeholder data until we can retrieve user data from front end
            KeyInfo info;
            info.name="Alice";
            info.id="123456789";

            //Step 1: Generate keys 
            cout << "Generating keys...\n";
            info.idKey=cryptography::genIDKeyPair();
            info.signedKey=cryptography::generateSignedPreKey(info.idKey);
            info.signedPreSig=cryptography::signPreKey(info.idKey, info.signedKey);
            info.oneTimeKeys=cryptography::genOneTimeKeys(10);

            info.idKey.priKey=cryptography::encryptKey(info.idKey.priKey);
            info.signedKey.priKey=cryptography::encryptKey(info.signedKey.priKey);
            for (auto& oneTimeKey : info.oneTimeKeys) {
                oneTimeKey.priKey = cryptography::encryptKey(oneTimeKey.priKey);
            }
            
            //Store the keys
            control.addKey(info);

            //Get peer info to set up the session
            KeyInfo retrieve;
            vector<unsigned char> peerKeyBundle;
            try{
                KeyInfo retrieve = control.getKey("2345678901");

                // Concatenate the keys into a single vector
                peerKeyBundle.insert(peerKeyBundle.end(), retrieve.idKey.pubKey.begin(), retrieve.idKey.pubKey.end());
                peerKeyBundle.insert(peerKeyBundle.end(), retrieve.signedKey.pubKey.begin(), retrieve.signedKey.pubKey.end());
                peerKeyBundle.insert(peerKeyBundle.end(), retrieve.signedPreSig.begin(), retrieve.signedPreSig.end());

                // Add all the one time keys that were created
                for (const auto &oneTimeKey : retrieve.oneTimeKeys){
                    peerKeyBundle.insert(peerKeyBundle.end(), oneTimeKey.pubKey.begin(), oneTimeKey.pubKey.end());
                }
            }
            catch (const runtime_error &e){
                cout << e.what() << endl;
            }

            //Establish the session
            auto session=cryptography::createSession(peerAddress, peerKeyBundle);

            //Encrypt the Message
            //receive message from front end
            string message;
            auto cipher=cryptography::encryptMessage(session, message);


            //Send Message
            SSL_write(ssl, message.data(), message.size());

            //Decrypt Message
            auto recCipher=cipher;
            auto decMessage=cryptography::decryptMessage(session, recCipher);

            SSL_shutdown(ssl);
            SSL_free(ssl);
            close(cSock);
        }
    }
    close(serveSock);
    SSL_CTX_free(ctx);
    cleanupOpenssl();
    cryptography::cleanup();

    return 0;
}