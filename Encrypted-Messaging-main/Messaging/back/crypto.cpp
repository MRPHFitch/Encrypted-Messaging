/**
 * @file Messaging
 * @author Nathan and Mason
 * @version 1.0
 * @date 2025-05-04
 * Description: Implement the .hpp logic. RSA key negotiation, Key chaining, AES, etc.
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
#include <openssl/aes.h>
#include <vector>
#include <string>
#include <cstring>
#include "headers/crypto.hpp"

using namespace std;

// Generates a random key of 32 bytes (256 bits).
vector<unsigned char> Crypto::generateRandKey() {
    vector<unsigned char> r;
    r.resize(32);
    RAND_bytes(r.data(), r.size());

    return r;
}

// Generates RSA key and public key cert and returns it in a structure.
RSAKeyPair Crypto::generateRSAKey() {
	// Generate RSA key
    RSA* rsa = RSA_new();
    BIGNUM* bne = BN_new();
    BN_set_word(bne, RSA_F4);
    RSA_generate_key_ex(rsa, 2048, bne, NULL);

	// Save public key as X509 certificate
    X509* cert = X509_new();
    EVP_PKEY* pkey = EVP_PKEY_new();
    EVP_PKEY_assign_RSA(pkey, rsa);
    X509_set_pubkey(cert, pkey);

    // Set keys in structure
	RSAKeyPair keyPair;
	keyPair.pubKey = cert;
	keyPair.priKey = rsa;

	// Clean up
    BN_free(bne);
    //RSA_free(rsa);
    //X509_free(cert);
	EVP_PKEY_free(pkey);

	return keyPair;
}

//This function signs the cert with an RSA private key 
X509* Crypto::signCert(X509* signCert, RSA* key) {
    //set cert information
	X509_set_version(signCert, 2); // Set version to X509v3
	X509_gmtime_adj(X509_get_notBefore(signCert), 0); // Set notBefore to current time
	X509_gmtime_adj(X509_get_notAfter(signCert), 31536000L); // Set notAfter to one year later
	X509_set_pubkey(signCert, EVP_PKEY_new()); // Set public key

	// Set the subject name to the issuer name (self-signed)
	X509_NAME* name = X509_get_subject_name(signCert);
	X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC, (unsigned char*)"Self-Signed Certificate", -1, -1, 0);
	
    // Set the issuer name to the subject name (self-signed)
	X509_set_issuer_name(signCert, name);

    // save RSA to useable format
	EVP_PKEY* signingKey = EVP_PKEY_new();
    EVP_PKEY_set1_RSA(signingKey, key);

	// Sign the certificate with the RSA private key
	int test = X509_sign(signCert, signingKey, EVP_sha256());
    if (test == 0) {
        std::cout << "not signing cert" << std::endl;
    }

	// Clean up
	EVP_PKEY_free(signingKey);


	return signCert;
}

// This function verifies the public key from a trusted source by checking the modulus and exponent against the certificate.
bool Crypto::verifyCert(X509* cert, X509* signKey) {
	// Retrieve the public key for verifiction
	EVP_PKEY* signingKey = EVP_PKEY_new();
	signingKey = X509_get_pubkey(signKey);

	//Verify the certificate using the public key
	int match = X509_verify(cert, signingKey);

	// Clean up
	EVP_PKEY_free(signingKey);

	// Return true if the verification was successful
	if (match != 1) {
		return false;
	}
    return true;

}

// This function initiates a session by generating a random key (R1) and signing it with the other party's public RSA key.
// Returns the signed key and plain random key
initiationInfo Crypto::initiateSession(X509* cert) {    
    // Extract partner's public key
    EVP_PKEY* pubKey = EVP_PKEY_new();
    RSA* rsa = RSA_new();
    pubKey = X509_get_pubkey(cert);
    rsa = EVP_PKEY_get1_RSA(pubKey);
    
    // Random key value
    vector<unsigned char> r1 = generateRandKey();
    vector<unsigned char> signR1; //will hold signed key

    signR1.resize(RSA_size(rsa));

    // Sign key
    int size = RSA_public_encrypt(r1.size(), r1.data(), signR1.data(), rsa, RSA_PKCS1_PADDING);
    signR1.resize(size);

	initiationInfo initInfo;
	initInfo.r1 = r1;
	initInfo.signR1 = signR1;

	// Clean Up
	RSA_free(rsa);
	EVP_PKEY_free(pubKey);

    return initInfo;
}

// This function generates a session key by decrypting the signed R with the public key from the certificate,
// and then XORing it with a new random key (R2). It also signs R2 to send back.
SessionInfo Crypto::generateSessionKey(RSA* rsa, X509* cert, vector<unsigned char> signR, vector<unsigned char> r = std::vector<unsigned char>()) {
    
    // Extract partner's public key
    EVP_PKEY* pubKey = EVP_PKEY_new();
    RSA* extractedPubKey = RSA_new();
    pubKey = X509_get_pubkey(cert);
    extractedPubKey = EVP_PKEY_get1_RSA(pubKey);

    // Verify
    vector<unsigned char> r1;
    r1.resize(32);
    RSA_private_decrypt(signR.size(), signR.data(), r1.data(), rsa, RSA_PKCS1_PADDING);

    // Print R1 in hex format for testing
    /*std::cout << "R1 (hex): ";
    for (size_t i = 0; i < r1.size(); i++) {
        printf("%02x", r1.at(i));
    }
    std::cout << std::endl;*/

    vector<unsigned char> r2;
    vector<unsigned char> signR2;

	// We don't have previous R, so we generate a new one
    if (r.empty()) {
        // If R is not provided, generate a new random key to XOR
        r2 = generateRandKey();

        // Sign R2 to send back
        signR2.resize(RSA_size(rsa));
        int size = RSA_public_encrypt(r2.size(), r2.data(), signR2.data(), extractedPubKey, RSA_PKCS1_PADDING);
        signR2.resize(size);
    }
    else { //r is already provided
        r2 = r;
		signR2 = std::vector<unsigned char>(); //no need to sign R2 if we are using an existing one
    }

	// Print R2 in hex format for testing
    /*std::cout << "R2 (hex): ";
    for (size_t i = 0; i < r2.size(); i++) {
        printf("%02x", r2.at(i));
    }
    std::cout << std::endl;*/

	// Generate session key from R1 XOR R2
	vector<unsigned char> sessionKey;
	sessionKey.resize(32);
    for (size_t i = 0; i < r1.size(); i++) {
        sessionKey.at(i) = r1.at(i) ^ r2.at(i);
    }

	// Create SessionInfo structure to hold session key and signed R2
	SessionInfo sessionInfo;
	sessionInfo.sessionKey = sessionKey;
	sessionInfo.signR = signR2;
    
    // Clean Up
    RSA_free(extractedPubKey);
    EVP_PKEY_free(pubKey);

	return sessionInfo;
}

// This function will take a the HMAC from the root key and derive a message key using HKDF.
vector <unsigned char> Crypto::HKDF(vector<unsigned char> MAC) {
	// Variable declarations
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

	// Set up parameters for HKDF
    *p++ = OSSL_PARAM_construct_utf8_string(OSSL_KDF_PARAM_DIGEST, const_cast<char*>("SHA256"), 0);
    *p++ = OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_KEY, MAC.data(), MAC.size());
    *p = OSSL_PARAM_construct_end();

    // Derive HKDF value
    EVP_KDF_CTX_set_params(kdfCtx, params);
    EVP_KDF_derive(kdfCtx, messageKey.data(), messageKey.size(), NULL);

	// Clean up
	EVP_KDF_CTX_free(kdfCtx);
	OSSL_LIB_CTX_free(libraryCtx);
    //free(p);

    return messageKey;
}

// This function will take a root key and generate an HMAC using SHA-256. Data should be 0 or 1 depending on key for chain
vector<unsigned char> Crypto::chainHMAC(vector<unsigned char> rootKey, int data) {
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

// Using a root key, this function generates a chain key pair, which includes a new root key and a message key.
vector<vector<unsigned char>> Crypto::generateChainKeyPair(vector<unsigned char> rootKey) {
	// Generate message key with HMAC followed by HKDF
	vector<unsigned char> messageKey = chainHMAC(rootKey, 0);

    // Generate next root key with HMAC and HKDF
	vector<unsigned char> x = chainHMAC(rootKey, 1);
	vector<unsigned char> nextRootKey = HKDF(x);

	vector<vector<unsigned char>> keyPair;
	keyPair.push_back(nextRootKey); //first element is the next root key
	keyPair.push_back(messageKey); //second element is new message key

	return keyPair;
}

// This function uses generateChainKeyPair to generate a root key (0), message key (1), IV (2), and HMAC Key (3) for AES encryption.
vector<vector<unsigned char>> Crypto::generateMessageKeys(vector<unsigned char> rootKey) {
	// Generate message key and next root
	vector<vector<unsigned char>> keyPair = generateChainKeyPair(rootKey);
	vector<unsigned char> nextRootKey = keyPair.at(0); //next root key
	vector<unsigned char> messageKey = keyPair.at(1); //message key

	// Generate IV using the next root key
	keyPair = generateChainKeyPair(nextRootKey);
	nextRootKey = keyPair.at(0); //next root key
	vector<unsigned char> iv = keyPair.at(1); //IV
	iv.resize(AES_BLOCK_SIZE); // Ensure IV is 16 bytes

	//Generate HMAC key using the next root key
	keyPair = generateChainKeyPair(nextRootKey);
	nextRootKey = keyPair.at(0); //next root key
	vector<unsigned char> HMAC = keyPair.at(1); //HMAC key

	//concatonate the keys into a vector of vectors
    vector<vector<unsigned char>> returnKeys;
	returnKeys.push_back(nextRootKey); //first element is the next root key
	returnKeys.push_back(messageKey); //second element is the message key
	returnKeys.push_back(iv); //third element is the IV
	returnKeys.push_back(HMAC); //fourth element is the HMAC key
	
	return returnKeys;
}

// This function encrypts a message using AES-256-CBC (PKCS#5 default) and returns the ciphertext along with its length.
EncryptedMessageData Crypto::encryptMessage(vector<unsigned char> key, vector<unsigned char> iv, vector<unsigned char> HMAC, string message) {
	// Convert message to unsigned char array plaintext
	vector<unsigned char> plaintext(message.begin(), message.end());
    
    // Initialize AES encryption
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    //int plaintext_len = strlen((const char*)plaintext);
    vector<unsigned char> ciphertext(plaintext.size() + AES_BLOCK_SIZE); // Allocate space for ciphertext
    int len;

    // Initialize the encryption operation
    if (EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key.data(), iv.data()) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        throw runtime_error("Error initializing encryption");
    }

    if (EVP_EncryptUpdate(ctx, ciphertext.data(), &len, plaintext.data(), plaintext.size()) != 1) {
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

    // Prepare ciphertext data before HMAC
    ciphertext = vector<unsigned char>(ciphertext.begin(), ciphertext.begin() + ciphertext_len);

    // Initialize HMAC
    EVP_MD_CTX* mdctx = EVP_MD_CTX_new();
    size_t hmacLen = 32;
    vector<unsigned char> hmacOut(EVP_MAX_MD_SIZE);

	// format key into EVP_PKEY
    EVP_PKEY* pkey = EVP_PKEY_new_raw_private_key(EVP_PKEY_HMAC, NULL, HMAC.data(), HMAC.size());
    // Generate HMAC
    if (EVP_DigestSignInit(mdctx, NULL, EVP_sha256(), NULL, pkey) != 1) {
        EVP_MD_CTX_free(mdctx);
        throw runtime_error("Error initializing HMAC");
    }
    if (EVP_DigestSignUpdate(mdctx, ciphertext.data(), ciphertext.size()) != 1) {
        EVP_MD_CTX_free(mdctx);
        throw runtime_error("Error during HMAC update");
    }
    if (EVP_DigestSignFinal(mdctx, hmacOut.data(), &hmacLen) != 1) {
        EVP_MD_CTX_free(mdctx);
        throw runtime_error("Error during HMAC finalization");
    }
    // Clean up
    EVP_MD_CTX_free(mdctx);

	//return ciphertext and HMAC
    return {ciphertext, hmacOut};
}

// This functions returns a boolean indicating whether the HMAC matches the computed HMAC for the given key and text
bool Crypto::verifyHMAC(vector<unsigned char> HMACKey, vector<unsigned char> data, vector<unsigned char> receivedHmac) {
    // Initialize HMAC
    EVP_MD_CTX* mdctx = EVP_MD_CTX_new();
    size_t hmacLen = 32;
    vector<unsigned char> hmacOut(EVP_MAX_MD_SIZE);

    // format key into EVP_PKEY
    EVP_PKEY* pkey = EVP_PKEY_new_raw_private_key(EVP_PKEY_HMAC, NULL, HMACKey.data(), HMACKey.size());
    // Generate HMAC
    EVP_DigestSignInit(mdctx, NULL, EVP_sha256(), NULL, pkey);
    EVP_DigestSignUpdate(mdctx, data.data(), data.size());
    EVP_DigestSignFinal(mdctx, hmacOut.data(), &hmacLen);

    // Clean up
    EVP_MD_CTX_free(mdctx);

	// Check if the computed HMAC matches the received HMAC
	for (size_t i = 0; i < hmacOut.size(); i++) {
		if (hmacOut.at(i) != receivedHmac.at(i)) {
			return false; // HMACs do not match
		}
	}

	return true; // HMACs match
}

//Decrypts a message using AES-256-CBC and verifies the HMAC before decryption (encrypt-then-authenticate used to make HMAC).
string Crypto::decryptMessage(vector<unsigned char> key, vector<unsigned char> iv, vector<unsigned char> HMACKey, vector<unsigned char> ciphertext, vector<unsigned char> hmac) {
	// Verify HMAC before decryption
    if (verifyHMAC(HMACKey, ciphertext, hmac)) {
        EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
        vector<unsigned char> plaintext(ciphertext.size()); // Allocate space for plaintext
        int len;

        // Initialize the decryption operation
        if (EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key.data(), iv.data()) != 1) {
            EVP_CIPHER_CTX_free(ctx);
            throw runtime_error("Error initializing decryption");
        }

        if (EVP_DecryptUpdate(ctx, plaintext.data(), &len, ciphertext.data(), ciphertext.size()) != 1) {
            EVP_CIPHER_CTX_free(ctx);
            throw runtime_error("Error during decryption update");
        }

        if (EVP_DecryptFinal_ex(ctx, plaintext.data() + len, &len) != 1) {
            EVP_CIPHER_CTX_free(ctx);
            throw runtime_error("Error during final decryption");
        }

        // Clean up
        EVP_CIPHER_CTX_free(ctx);

        return string(reinterpret_cast<char*>(plaintext.data()), plaintext.size());
    }   
	else { //HMAC verification failed
        return "The message has been tampered with!!!!";
    }
}

//I had this function named main and commented out main.cpp to test crypto process
// int test() {
//     Person Alice, Bob;
// 	Server server;

// 	// Generate RSA keys for Alice and Bob
// 	RSAKeyPair aliceKeyPair = generateRSAKey();
// 	RSAKeyPair bobKeyPair = generateRSAKey();
// 	RSAKeyPair serverKeyPair = generateRSAKey();

//     //Save all private keys
//     Alice.myPriKey = aliceKeyPair.priKey;
//     Bob.myPriKey = bobKeyPair.priKey;
//     server.serverPriKey = serverKeyPair.priKey;

// 	// Set server public key for Alice and Bob
// 	Alice.serverPubKey = serverKeyPair.pubKey;
// 	Bob.serverPubKey = serverKeyPair.pubKey;
// 	server.serverPubKey = serverKeyPair.pubKey;
	
//     // send public keys to server
// 	server.AlicePubKey = aliceKeyPair.pubKey;
// 	server.BobPubKey = bobKeyPair.pubKey;
    
// 	//Alice retrieves bob's public key from server
// 	if (!verifyCert(signCert(server.BobPubKey, server.serverPriKey), Alice.serverPubKey)) {
// 		std::cout << "Bob's public key verification failed!" << std::endl;
// 		return 1; // Exit if verification fails
// 	}
//     Alice.theirPubKey = server.BobPubKey;

// 	// Alice initiates session
// 	initiationInfo initInfo = initiateSession(Alice.theirPubKey);

// 	//Bob retrives Alice's public key from server
// 	if (!verifyCert(signCert(server.AlicePubKey, server.serverPriKey), Bob.serverPubKey)) {
// 		std::cout << "Alice's public key verification failed!" << std::endl;
// 		return 1; // Exit if verification fails
// 	}
//     Bob.theirPubKey = server.AlicePubKey;

// 	// Bob generates session key and R2
// 	SessionInfo bobSessionInfo = generateSessionKey(Bob.myPriKey, Bob.theirPubKey, initInfo.signR1); //remove printing
// 	Bob.rootKey = bobSessionInfo.sessionKey;

//     // Alice generates Session Key with Signed R2
// 	SessionInfo aliceSessionInfo = generateSessionKey(Alice.myPriKey, Alice.theirPubKey, bobSessionInfo.signR, initInfo.r1);
// 	Alice.rootKey = aliceSessionInfo.sessionKey;

//     // Show that Hex keys match
//     std::cout << "Alice Key (hex): ";
//     for (size_t i = 0; i < Alice.rootKey.size(); i++) {
//         printf("%02x", Alice.rootKey.at(i));
//     }
// 	std::cout << std::endl;

// 	std::cout << "Bob Key (hex): ";
// 	for (size_t i = 0; i < Bob.rootKey.size(); i++) {
// 		printf("%02x", Bob.rootKey.at(i));
// 	}
// 	std::cout << std::endl;

// 	//Alice generates key and IV to send her encrypted message
// 	vector<vector<unsigned char>> aliceKeys = generateMessageKeys(Alice.rootKey);
// 	Alice.rootKey = aliceKeys.at(0);
//     Alice.messageKey = aliceKeys.at(1); //message key
// 	Alice.iv = aliceKeys.at(2);
// 	Alice.HMACKey = aliceKeys.at(3);

// 	//Alice encrypts a message to Bob
//     EncryptedMessageData encrypted = encryptMessage(Alice.messageKey, Alice.iv, Alice.HMACKey, "Hello, Bob! This is Alice's message.");

//     //Data is sent to bob

// 	//Bob receives the encrypted message and generates his own key and IV
//     vector<vector<unsigned char>> bobKeys = generateMessageKeys(Bob.rootKey);
//     Bob.rootKey = bobKeys.at(0);
//     Bob.messageKey = bobKeys.at(1); //message key
//     Bob.iv = bobKeys.at(2);
// 	Bob.HMACKey = bobKeys.at(3);

// 	//Bob decrypts the message
// 	std::cout << std::endl << decryptMessage(Bob.messageKey, Bob.iv, Bob.HMACKey, encrypted.ciphertext, encrypted.hmac) << std::endl;

//     return 0;
// }
