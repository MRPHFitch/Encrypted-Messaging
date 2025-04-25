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
#include <string>
#include <vector>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include "crypto.hpp"

void print_hex(const std::vector<unsigned char>& data) {
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
    std::cout << "Generating Diffie-Hellman parameters...\n";
    DH* dh = cryptography::generate_dh_params();

    // Step 2: Generate DH public key
    BIGNUM* pubKeyBn = BN_new();
    DH_get0_key(dh, &pubKeyBn, nullptr);

    // Step 3: Convert public key to bytes and display it
    std::vector<unsigned char> pubKeyBytes(DH_size(dh));
    int len = BN_bn2bin(pubKeyBn, pubKeyBytes.data());
    pubKeyBytes.resize(len);

    std::cout << "My public key (hex): ";
    print_hex(pubKeyBytes);

    // Step 4: Send public key to peer (simulated in this example)
    // Normally you would send `pubKeyBytes` over a socket to the peer.

    // Step 5: Assume we receive the peer's public key (simulated here)
    // In a real system, this would come from the peer via network communication
    std::cout << "Enter peer's public key (hex): ";
    std::string peerKeyHex;
    std::cin >> peerKeyHex;

    // Convert peer's public key from hex string to bytes
    std::vector<unsigned char> peerKey = cryptography::hex_to_bytes(peerKeyHex);

    // Step 6: Generate shared secret using peer's public key
    std::cout << "Generating shared secret...\n";
    std::vector<unsigned char> sessionKey = cryptography::generate_shared_secret(dh, peerKey);
    
    std::cout << "Shared secret (hex): ";
    print_hex(sessionKey);

    // Step 7: Generate AES key from the shared secret (for simplicity, use part of the secret)
    std::vector<unsigned char> aesKey(sessionKey.begin(), sessionKey.begin() + 32);  // AES-256 requires 32 bytes

    std::cout << "AES key (hex): ";
    print_hex(aesKey);

    // Step 8: Encrypt and send a message to the peer
    std::string message = "Hello, Peer! This is a secret message.";
    std::vector<unsigned char> encMessage = cryptography::aes_encrypt(
        std::vector<unsigned char>(message.begin(), message.end()), aesKey);
    
    std::cout << "Encrypted message (hex): ";
    print_hex(encMessage);

    // Step 9: Simulate sending the encrypted message over a network
    // Normally this would be done via a socket, but we can just "send" it here

    // Step 10: Decrypt the message on the receiving side (same peer)
    std::vector<unsigned char> decMessage = cryptography::aes_decrypt(encMessage, aesKey);
    
    std::cout << "Decrypted message: ";
    std::string decrypted_str(decMessage.begin(), decMessage.end());
    std::cout << decrypted_str << std::endl;

    // Clean up OpenSSL
    DH_free(dh);
    OPENSSL_cleanup();

    return 0;
}
