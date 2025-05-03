/**
 * @file Messaging
 * @author Matthew Fitch
 * @version 2.0
 * @date 2025-04-16
 * @details: Functions for both Client and Server side of things. Sets up a KDC, encrypts necessary 
 * keys before placing into KDC, and retrieves all information of users involved and establishes a chat.
 * Once session established, retrieves message from front end, encrypts the message, and sends it to the peer.
 * Peer then decrypts message, and has it sent to front end to display. 
 * 
*/
#include <iostream>
#include <cstdio>
#include <string>
#include <vector>
#include <thread>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <boost/asio.hpp>
#include <boost/asio/ssl.hpp>
#include <unistd.h>
#include <unordered_map>
#include <mutex>
#include "crypto.hpp"
#include "socketHandler.cpp"

using namespace std;
namespace ssl=net::ssl;

struct KeyInfo{
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
void printHex(const vector<unsigned char>& data){
    for (unsigned char byte : data) {
        printf("%02x", byte);
    }
    printf("\n");
}

void sendMessageFront(string& name, string& plaintext, string& ciphertext){
    lock_guard<mutex> lock(connMutex);
    auto it=clients.find(name);
    if(it!=clients.end()){
        try{
            json messageJson={
                {"type", "message"},
                {"plaintext", plaintext},
                {"ciphertext", ciphertext}
            };
            string messageString=messageJson.dump();
            it->second->text(true);
            it->second->write(net::buffer(messageString));
            cout<<"Message sent to: "<<name<<endl;
        }
        catch(exception e){
            cerr<<"Error sending message: "<<e.what()<<endl;
        }
    }
    else{
        cerr<<"Client not connected."<<endl;
    }
}
int main() {
    try{
        net::io_context ioc;
        ssl::context ctx{ssl::context::tlsv12};

        ctx.use_certificate_file("server.cert", ssl::context::pem);
        ctx.use_certificate_file("server.key", ssl::context::pem);
        tcp::acceptor acceptor{ioc, {tcp::v4(), 49250}};

        for(;;){
            tcp::socket socket{ioc};
            acceptor.accept(socket);
            auto ws=make_shared<WebSocketStream>(std::move(socket), ctx);
            thread{bind(&doSession, ws)}.detach();
        }
    }
    catch(exception const& e){
        cerr<<"Error: "<<e.what()<<endl;
    }
    string recipientId="someRecipientId";
    auto recipConnection= getClientConnection(recipientId);
    if(recipConnection){
        recipConnection->text(true);
        recipConnection->write(net::buffer("Hello, recipient!"));
    }
    //Initialize KDC and crypto file
    KDC control;

    cryptography::initialize();
    while(1){
        // Placeholder data until we can retrieve user data from front end
        KeyInfo info;

        // Step 1: Generate keys
        cout << "Generating keys...\n";
        info.idKey = cryptography::genIDKeyPair();
        info.signedKey = cryptography::generateSignedPreKey(info.idKey);
        info.signedPreSig = cryptography::signPreKey(info.idKey, info.signedKey);
        info.oneTimeKeys = cryptography::genOneTimeKeys(10);

        info.idKey.priKey = cryptography::encryptKey(info.idKey.priKey);
        info.signedKey.priKey = cryptography::encryptKey(info.signedKey.priKey);
        for (auto &oneTimeKey : info.oneTimeKeys){
            oneTimeKey.priKey = cryptography::encryptKey(oneTimeKey.priKey);
        }

        // Store the keys
        control.addKey(info);

        // Get peer info to set up the session
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
        //////////////////////////////////////////////////////////////////////////////////
        //////////////////////////////////////////////////////////////////////////////////
        //////////////////////////////////////////////////////////////////////////////////
        //NEED TO RETRIEVE THIS FROM FRONT END
        string recipientName;
        string peerAddress=findIp(recipientName);

        // Get message from front end, establish a session, encrypt the message
        auto messageReceived=[peerAddress, &peerKeyBundle, &recipientName](const string& message){
            auto session = cryptography::createSession(peerAddress, peerKeyBundle);
            auto cipher = cryptography::encryptMessage(session, message);
            auto recipConnection=getClientConnection(recipientName);
            if(recipConnection){
                try{
                    recipConnection->text(true);
                    recipConnection->write(net::buffer(cipher));
                }
                catch(exception e){
                    cerr<<"Error sending message: "<<e.what()<<endl;
                }
            }
            else{
                cerr<<"Recipient not found."<<endl;
            }
            string recCipher = cipher;
            auto decMessage = cryptography::decryptMessage(session, recCipher);
            sendMessageFront(recipientName, decMessage, cipher);
        };
    }
    cryptography::cleanup();
    return 0;
}