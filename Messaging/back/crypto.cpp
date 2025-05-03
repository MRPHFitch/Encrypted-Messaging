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
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/x509.h>
#include <openssl/kdf.h>
#include <openssl/params.h>
#include <openssl/core_names.h>
#include <openssl/err.h>
#include <vector>
#include <string>
#include <cstring>
#include "headers/crypto.hpp"

using namespace std;

// This function is not implemented for use yet, shows working RSA tools
int generateSessionKey() {
    // Generate RSA key pair
    RSA* rsa = RSA_new();
    BIGNUM* bne = BN_new();
    BN_set_word(bne, RSA_F4);
    RSA_generate_key_ex(rsa, 2048, bne, NULL); 
    
    // Random key value
    vector<unsigned char> r1;
    r1.resize(32);
    unsigned char* signR;
    RAND_bytes(r1.data(), r1.size());

    vector<unsigned char> recovered;
    recovered.resize(32);

    std::cout << "R1 (hex): ";
    for (size_t i = 0; i < r1.size(); i++) {
        printf("%02x", r1.at(i));
    }
    std::cout << std::endl;
    
    signR = (unsigned char*)malloc(RSA_size(rsa));

    // Sign
    int size = RSA_private_encrypt(r1.size(), r1.data(), signR, rsa, RSA_PKCS1_PADDING);

    // Save public key
    X509* cert = X509_new();
    EVP_PKEY* pkey = EVP_PKEY_new();
    EVP_PKEY_assign_RSA(pkey, rsa);
    X509_set_pubkey(cert, pkey);

    // Extract public key
    EVP_PKEY* pubKey = EVP_PKEY_new();
    RSA* extracted = RSA_new();
    pubKey = X509_get_pubkey(cert);
    extracted = EVP_PKEY_get1_RSA(pubKey);

    // Verify
    RSA_public_decrypt(size, signR, recovered.data(), extracted, RSA_PKCS1_PADDING);

    std::cout << "Recovered (hex): ";
    for (size_t i = 0; i < recovered.size(); i++) {
        printf("%02x", recovered.at(i));
    }
    std::cout << std::endl;
    
    // Clean Up
    BN_free(bne);
    RSA_free(rsa);
    RSA_free(extracted);
    EVP_PKEY_free(pkey);
    EVP_PKEY_free(pubKey);
    X509_free(cert);
    free(signR); //heap corruption error

	return 0;
}

// This function will take a the HMAC from the root key and derive a message key using HKDF.
vector <unsigned char> HKDF(vector<unsigned char> MAC) {
//int main() {
    /*vector<unsigned char> key;
    key.resize(32);
    RAND_bytes(key.data(), key.size());*/

    EVP_KDF* kdf = NULL;
    EVP_KDF_CTX* kdfCtx = NULL;
    vector<unsigned char> messageKey;
	messageKey.resize(32);
    OSSL_PARAM params[5], * p = params;
    OSSL_LIB_CTX* libraryCtx = NULL;

	// Initialize OpenSSL library context
    libraryCtx = OSSL_LIB_CTX_new();

    kdf = EVP_KDF_fetch(libraryCtx, "HKDF", NULL);
    kdfCtx = EVP_KDF_CTX_new(kdf);
    EVP_KDF_free(kdf);

    *p++ = OSSL_PARAM_construct_utf8_string(OSSL_KDF_PARAM_DIGEST, const_cast<char*>("SHA256"), 0);
    *p++ = OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_KEY, MAC.data(), MAC.size());
    *p = OSSL_PARAM_construct_end();

    EVP_KDF_CTX_set_params(kdfCtx, params);

    EVP_KDF_derive(kdfCtx, messageKey.data(), messageKey.size(), NULL);

	// Clean up
	EVP_KDF_CTX_free(kdfCtx);
	OSSL_LIB_CTX_free(libraryCtx);
    //free(p);

    return messageKey;
}

// This function will take a root key and generate an HMAC using SHA-256.
vector<unsigned char> HMAC(vector<unsigned char> rootKey, int data) {
    // Make rootKey into EVP_PKEY
    EVP_PKEY* key = EVP_PKEY_new_raw_private_key(EVP_PKEY_HMAC, NULL, rootKey.data(), rootKey.size());
    
    // Initialize HMAC
    EVP_MD_CTX* mdctx = EVP_MD_CTX_new();
    size_t hmacLen = 32;
    vector <unsigned char> hmacOut;
	hmacOut.resize(hmacLen);

    // Generate HMAC
    EVP_DigestSignInit(mdctx, NULL, EVP_sha256(), NULL, key);
    EVP_DigestSignUpdate(mdctx, &data, sizeof(data));
    EVP_DigestSignFinal(mdctx, hmacOut.data(), &hmacLen);

	// Clean up
	EVP_MD_CTX_free(mdctx);
	EVP_PKEY_free(key);

	return hmacOut;
}

vector<vector<unsigned char>> generateChainKeyPair(vector<unsigned char> rootKey) {
	// Generate message key with HMAC followed by HKDF
	vector<unsigned char> messageKey = HMAC(rootKey, 0);

    // Generate next root key with HMAC and HKDF
	vector<unsigned char> x = HMAC(rootKey, 1);
	vector<unsigned char> nextRootKey = HKDF(x);

	vector<vector<unsigned char>> keyPair;
	keyPair.push_back(nextRootKey); //first element is the next root key
	keyPair.push_back(messageKey); //second element is new message key

	return keyPair;
}

//This was just to test chain was working correctly
/*int chainTest() {
    vector<unsigned char> key;
    key.resize(32);
    RAND_bytes(key.data(), key.size());

	std::cout << "Key (hex): ";
	for (size_t i = 0; i < key.size(); i++) {
		printf("%02x", key.at(i));
	}
	std::cout << std::endl;

	vector<vector<unsigned char>> keyPair = generateChainKeyPair(key);
	std::cout << "Next Root Key (hex): ";
	for (size_t i = 0; i < keyPair[0].size(); i++) {
		printf("%02x", keyPair[0].at(i));
	}
	std::cout << std::endl;

	std::cout << "Message Key (hex): ";
	for (size_t i = 0; i < keyPair[1].size(); i++) {
		printf("%02x", keyPair[1].at(i));
	}
	std::cout << std::endl;

    return 0;
}*/

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

