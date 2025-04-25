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
#include "crypto.hpp"

using namespace std;

void print_hex(const vector<unsigned char>& data) {
    for (unsigned char byte : data) {
        printf("%02x", byte);
    }
    printf("\n");
}

int main() {
    // Initialize OpenSSL (for SSL/TLS, but also used by DH, AES, etc.)
    SSL_library_init();
    OpenSSL_add_all_algorithms();
    OPENSSL_config(nullptr);

    // Step 1: Generate Diffie-Hellman parameters (shared settings)
    cout << "Generating Diffie-Hellman parameters...\n";
    DH* dh = cryptography::generate_dh_params();

    // Step 2: Generate DH public key
    BIGNUM* pubKeyBn = BN_new();
    DH_get0_key(dh, &pubKeyBn, nullptr);

    // Step 3: Convert public key to bytes and display it
    vector<unsigned char> pubKeyBytes(DH_size(dh));
    int len = BN_bn2bin(pubKeyBn, pubKeyBytes.data());
    pubKeyBytes.resize(len);

    cout << "My public key (hex): ";
    print_hex(pubKeyBytes);

    // Step 4: Send public key to peer (simulated in this example)
    // Normally you would send `pubKeyBytes` over a socket to the peer.

    // Step 5: Assume we receive the peer's public key (simulated here)
    // In a real system, this would come from the peer via network communication
    cout << "Enter peer's public key (hex): ";
    string peerKeyHex;
    cin >> peerKeyHex;

    // Convert peer's public key from hex string to bytes
    vector<unsigned char> peerKey = cryptography::hex_to_bytes(peerKeyHex);

    // Step 6: Generate shared secret using peer's public key
    cout << "Generating shared secret...\n";
    vector<unsigned char> sessionKey = cryptography::generate_shared_secret(dh, peerKey);
    
    cout << "Shared secret (hex): ";
    print_hex(sessionKey);

    // Step 7: Generate AES key from the shared secret (for simplicity, use part of the secret)
    vector<unsigned char> aesKey(sessionKey.begin(), sessionKey.begin() + 32);  // AES-256 requires 32 bytes

    cout << "AES key (hex): ";
    print_hex(aesKey);

    // Step 8: Encrypt and send a message to the peer
    string message = "Hello, Peer! This is a secret message.";
    vector<unsigned char> encMessage = cryptography::aes_encrypt(
        vector<unsigned char>(message.begin(), message.end()), aesKey);
    
    cout << "Encrypted message (hex): ";
    print_hex(encMessage);

    // Step 9: Simulate sending the encrypted message over a network
    // Normally this would be done via a socket, but we can just "send" it here

    // Step 10: Decrypt the message on the receiving side (same peer)
    vector<unsigned char> decMessage = cryptography::aes_decrypt(encMessage, aesKey);
    
    cout << "Decrypted message: ";
    string decrypted_str(decMessage.begin(), decMessage.end());
    cout << decrypted_str << endl;

    // Clean up OpenSSL
    DH_free(dh);
    OPENSSL_cleanup();

    return 0;
}
