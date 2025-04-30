/**
 * @file Messaging
 * @author Nathan or Mason
 * @version 1.0
 * @date 2025-04-16
 * Description: Function Declarations, including necessary cryptographic functions
 * 
*/

using namespace std;

struct KeyPair{
    vector<unsigned char>pubKey;
    vector<unsigned char>priKey;
};

struct Session{

};
//Don't have to use this name, just let Matthew F. know what you do use.


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

    vector<unsigned char> encryptMessage(Session sesh, string message){}

    string decryptMessage(Session sesh, vector<unsigned char> message){}

    void cleanup(){}
}