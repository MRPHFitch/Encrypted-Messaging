/**
 * @file Messaging
 * @author Nathan
 * @version 1.0
 * @date 2025-05-03
 * Description: Function Declarations, including necessary cryptographic functions
 * 
*/

using namespace std;

struct RSAKeyPair{
    X509* pubKey;
    RSA* priKey;
};

struct initiationInfo {
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
	RSA* myPriKey;
	X509* theirPubKey;
};


namespace cryptography{

    void initialize(){}

	//Generates RSA key and public key cert and returns it in a structure.
    RSAKeyPair generateRSAKey() {}

    //This function initiates a session by generating a random key (R1) and signing it with the private RSA key.
    //Returns the signed key and plain random key
    initiationInfo initiateSession(RSA *rsa) {}

    //This function generates a session key by decrypting the signed R with the public key from the certificate,
    //and then XORing it with a new random key (R2). It also signs R2 to send back.
    SessionInfo generateSessionKey(RSA* rsa, X509* cert, vector<unsigned char> signR, vector<unsigned char> r = std::vector<unsigned char>()) {}

    //This function uses a root key to chain generate a root key (0), message key (1), and IV (2) for AES encryption.
    vector<vector<unsigned char>> generateMessageKeyAndIV(vector<unsigned char> rootKey) {}

    //This function encrypts a message using AES-256-CBC (PKCS#5 default) and returns the ciphertext along with its length.
    EncryptedMessageData encryptMessage(vector<unsigned char> key, vector<unsigned char> iv, string message) {}

    //This functions returns a boolean indicating whether the HMAC matches the computed HMAC for the given key and text
    bool verifyHMAC(vector<unsigned char> key, vector<unsigned char> data, vector<unsigned char> receivedHmac) {}

    //Decrypts a message using AES-256-CBC and verifies the HMAC before decryption (encrypt-then-authenticate used to make HMAC).
    string decryptMessage(vector<unsigned char> key, vector<unsigned char> iv, vector<unsigned char> ciphertext, vector<unsigned char> hmac) {}

    void cleanup(){}
}
