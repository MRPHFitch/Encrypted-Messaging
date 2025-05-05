/**
 * @file Messaging
 * @author Nathan
 * @version 1.0
 * @date 2025-05-04
 * Description: Function Declarations, including necessary cryptographic functions
 * 
*/

#ifndef CRYPTO_HPP
#define CRYPTO_HPP

#include <vector>
#include <string>
#include <openssl/rsa.h>
#include <openssl/x509.h>

using namespace std;

struct RSAKeyPair{
    X509* pubKey;
    RSA* priKey;
};

struct initationInfo {
	vector<unsigned char> r1;
	vector<unsigned char> signR1; 
};

struct SessionInfo {
	vector<unsigned char> sessionKey;
	vector<unsigned char> signR;
};

struct EncryptedMessageData {
    vector<unsigned char> ciphertext;
    vector<unsigned char> hmac;
};

// For testing
struct Person {
    vector<unsigned char> rootKey;
	vector<unsigned char> messageKey;
	vector<unsigned char> iv;
	vector<unsigned char> HMACKey;
	RSA* myPriKey;
	X509* theirPubKey;
	X509* serverPubKey;
};
struct Server {
    RSA* serverPriKey;
    X509* serverPubKey;
	X509* AlicePubKey;
	X509* BobPubKey;
};

namespace cryptography{
    // Function declarations
    RSAKeyPair generateRSAKey();
    X509* signCert(X509* signCert, RSA* key);
    bool verifyCert(X509* cert, X509* signKey);
    initationInfo initiateSession(X509* cert);
    SessionInfo generateSessionKey(RSA* rsa, X509* cert, vector<unsigned char> signR, vector<unsigned char> r = std::vector<unsigned char>());
    vector<vector<unsigned char>> generateMessageKeys(vector<unsigned char> rootKey);
    EncryptedMessageData encryptMessage(vector<unsigned char> key, vector<unsigned char> iv, vector<unsigned char> HMAC, string message);
    bool verifyHMAC(vector<unsigned char> HMACKey, vector<unsigned char> data, vector<unsigned char> receivedHmac);
    string decryptMessage(vector<unsigned char> key, vector<unsigned char> iv, vector<unsigned char> HMACKey, vector<unsigned char> ciphertext, vector<unsigned char> hmac);
    void cleanup();
}

class Crypto {
private:
    vector<unsigned char> generateRandKey();

public:
    RSAKeyPair generateRSAKey();
    X509* signCert(X509* signCert, RSA* key);
    bool verifyCert(X509* cert, X509* signKey)
    initationInfo initiateSession(X509* cert);
    SessionInfo generateSessionKey(RSA* rsa, X509* cert, vector<unsigned char> signR, vector<unsigned char> r = std::vector<unsigned char>());
    vector<vector<unsigned char>> generateMessageKeys(vector<unsigned char> rootKey);
    EncryptedMessageData encryptMessage(vector<unsigned char> key, vector<unsigned char> iv, vector<unsigned char> HMAC, string message);
    bool verifyHMAC(vector<unsigned char> HMACKey, vector<unsigned char> data, vector<unsigned char> receivedHmac);
    string decryptMessage(vector<unsigned char> key, vector<unsigned char> iv, vector<unsigned char> HMACKey, vector<unsigned char> ciphertext, vector<unsigned char> hmac);
    vector<unsigned char> HKDF(vector<unsigned char> MAC);
    vector<unsigned char> chainHMAC(vector<unsigned char> rootKey, int data);
    vector<vector<unsigned char>> generateChainKeyPair(vector<unsigned char> rootKey);
};

#endif // CRYPTO_HPP
