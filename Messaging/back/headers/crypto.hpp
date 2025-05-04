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
	RSA* myPriKey;
	X509* theirPubKey;
};


namespace cryptography{

    void initialize(){}

    //Please also ensure that for the Identity Key, Signed Pre Key, and One Time Keys keys generated, 
    //you return a KeyPair object as shown above.
    KeyPair genIDKeyPair(){}

    KeyPair generateSignedPreKey(KeyPair idkey){}

    vector<unsigned char> signPreKey(KeyPair idkey, KeyPair signPreKey){}

    vector<KeyPair> genOneTimeKeys(int num){}

    Session createSession(string addr, vector<unsigned char> keyBundle){}

    vector<unsigned char> encryptKey(vector<unsigned char>priKey){}

    string encryptMessage(Session sesh, string message){}

    string decryptMessage(Session sesh, string message){}

    void cleanup(){}
}
