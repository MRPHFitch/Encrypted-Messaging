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
    RSAKeyPair keys;
    initiationInfo initInfo;
    vector<vector<unsigned char>> messageKeys;
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
    //Initialize KDC and crypto file
    KDC control;
    string peerAddress;
    try{
        cout << "Setting up server..." << endl;
        net::io_context ioc;
        ssl::context ctx{ssl::context::tlsv12};

        // Load the server cert and private key
        ctx.use_certificate_file("server.crt", ssl::context::pem);
        ctx.use_certificate_file("server.key", ssl::context::pem);
        cout << "Setting up acceptor..." << endl;
        boost::system::error_code ec;
        tcp::acceptor acceptor{ioc};
        acceptor.open(tcp::v4(), ec);
        if (ec) {
            cerr << "Error opening WS acceptor: " << ec.message() << endl;
            return 1;
        }
        acceptor.set_option(tcp::acceptor::reuse_address(true));
        acceptor.bind(tcp::endpoint(tcp::v4(), 8081), ec);
        if (ec) {
            cerr << "Error binding WS acceptor: " << ec.message() << endl;
            return 1;
        }
        acceptor.listen(boost::asio::socket_base::max_listen_connections, ec);
        if (ec) {
            cerr << "Error listening on WS acceptor: " << ec.message() << endl;
            return 1;
        }
        cout << "Server listening on port 8081..." << endl;
        
        auto handleConn = [](tcp::socket socket, ssl::context& ctx) {
            try {
                std::cout << "New connection from: " << socket.remote_endpoint().address().to_string() 
                          << ":" << socket.remote_endpoint().port() << std::endl;
        
                // Create an SSL stream and perform the SSL handshake
                auto ssl_stream = std::make_shared<ssl::stream<tcp::socket>>(std::move(socket), ctx);
                ssl_stream->handshake(ssl::stream_base::server);
        
                // Create a WebSocket stream using the SSL stream
                auto ws = std::make_shared<WebSocketStream>(std::move(*ssl_stream));
        
                std::thread t([ws]() {
                    try {
                        std::cout << "Starting session..." << std::endl;
                        doSession(ws);
                        std::cout << "Session ended" << std::endl;
                    } catch (const std::exception& e) {
                        std::cerr << "Error in session: " << e.what() << std::endl;
                    }
                });
                t.detach();
            } catch (const std::exception& e) {
                std::cerr << "Error handling connection: " << e.what() << std::endl;
            }
        };
        
        // Endless loop for the connection
        for (;;){
            tcp::socket sock{ioc};
            cout << "Waiting for connection on port 8081..." << endl;
            acceptor.accept(sock);
            cout << "New connection accepted" << endl;
            auto ws = make_shared<WebSocketStream>(std::move(sock), ctx);
            std::thread{handleConn, ws}.detach();
        }
    }
    catch(exception const &e){
        cerr<<"Error: "<<e.what()<<endl;
    }
    
    while(1){
        // Placeholder data until we can retrieve user data from front end
        KeyInfo info;

        // Step 1: Generate keys
        cout << "Generating keys...\n";
        info.keys=session;
        info.messageKeys=messageAndIV;
        info.initInfo=initInfo;
        

        // Store the keys
        control.addKey(info);

        // Get peer info to set up the session
        KeyInfo retrieve;
        string recipientId;
        

        try{
            recipientId=getRecipient();
            peerAddress=findIp(recipientId);
        }
        catch(const runtime_error &e){
            cout<<e.what()<<endl;
        }
        try{
            KeyInfo retrieve = control.getKey(recipientId);
        }
        catch (const runtime_error &e){
            cout << e.what() << endl;
        }
        
    }
    peerAddress="";
    cryptography::cleanup();
    return 0;
}