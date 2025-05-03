/**
 * @file Messaging
 * @author Nathan or Mason
 * @version 1.0
 * @date 2025-04-16
 * Description: Implement the .hpp logic. D-H, Key exchange, AES, etc.
 * 
*/

#include <iostream>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/rand.h>
#include <openssl/core_names.h>
#include <openssl/err.h>
#include <vector>
#include <string>
#include <cstring>
#include "headers/crypto.hpp"

using namespace std;

EncryptedData encryptMessage(const unsigned char *key, const unsigned char *iv, const unsigned char *plaintext) {
    // Initialize AES encryption
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
	int plaintext_len = strlen((const char *)plaintext);
    vector<unsigned char> ciphertext(plaintext_len + AES_BLOCK_SIZE); // Allocate space for ciphertext
    int len;

    // Initialize the encryption operation
    if (EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        throw runtime_error("Error initializing encryption");
    }

    if (EVP_EncryptUpdate(ctx, ciphertext.data(), &len, plaintext, plaintext_len) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        throw runtime_error("Error during encryption update");
    }
    int ciphertext_len = len;

    if (EVP_EncryptFinal_ex(ctx, ciphertext.data() + len, &len) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        throw runtime_error("Error during final encryption");
    }
    ciphertext_len += len;

    // Clean up
    EVP_CIPHER_CTX_free(ctx);

    // Prepare data for HMAC
    vector<unsigned char> data(iv, iv + AES_BLOCK_SIZE);
    data.insert(data.end(), ciphertext.begin(), ciphertext.begin() + ciphertext_len);

    // Initialize HMAC
    EVP_MD_CTX *mdctx = EVP_MD_CTX_new();
    unsigned int hmac_len;
	vector<unsigned char> hmac_out(EVP_MAX_MD_SIZE);

    // Generate HMAC
    if (EVP_DigestSignInit(mdctx, NULL, EVP_sha256(), NULL, key) != 1) {
        EVP_MD_CTX_free(mdctx);
        throw runtime_error("Error initializing HMAC");
    }
    if (EVP_DigestSignUpdate(mdctx, data.data(), data.size()) != 1) {
        EVP_MD_CTX_free(mdctx);
        throw runtime_error("Error during HMAC update");
    }
    if (EVP_DigestSignFinal(mdctx, hmac_out.data(), &hmac_len) != 1) {
        EVP_MD_CTX_free(mdctx);
        throw runtime_error("Error during HMAC finalization");
    }
    // Clean up
    EVP_MD_CTX_free(mdctx);

    return {vector<unsigned char>(ciphertext.begin(), ciphertext.begin() + ciphertext_len), ciphertext_len}; // Return the ciphertext
}

bool verifyHMAC(const unsigned char *key, const unsigned char *data, size_t data_len, const unsigned char *received_hmac, size_t hmac_len) {
    // Buffer to hold the computed HMAC
    unsigned char computed_hmac[EVP_MAX_MD_SIZE];
    unsigned int computed_hmac_len;

    // Compute HMAC
    HMAC(EVP_sha256(), key, strlen((const char *)key), data, data_len, computed_hmac, &computed_hmac_len);

    // Compare computed HMAC with received HMAC
    if (computed_hmac_len != hmac_len) {
        return false; // Lengths do not match
    }

    return (memcmp(computed_hmac, received_hmac, computed_hmac_len) == 0);
}

string decryptMessage(const unsigned char *key, const unsigned char *iv, const vector<unsigned char> &ciphertext, int ciphertext_len)
{
	EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    vector<unsigned char> plaintext(ciphertext_len); // Allocate space for plaintext
    int len;

	// Initialize the decryption operation
    if (EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        throw runtime_error("Error initializing decryption");
    }

    if (EVP_DecryptUpdate(ctx, plaintext.data(), &len, ciphertext.data(), ciphertext_len) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        throw runtime_error("Error during decryption update");
    }
    int plaintext_len = len;

    if (EVP_DecryptFinal_ex(ctx, plaintext.data() + len, &len) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        throw runtime_error("Error during final decryption");
    }
    plaintext_len += len;

    // Clean up
    EVP_CIPHER_CTX_free(ctx);

    return string(reinterpret_cast<char*>(plaintext.data()), plaintext_len);
}

