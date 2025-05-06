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
#include <boost/beast/core.hpp>
#include <boost/beast/websocket.hpp>
#include <boost/beast/http.hpp>
#include <unistd.h>
#include <unordered_map>
#include <mutex>
#include "crypto.hpp"
#include "json.hpp"
#include "socketHandler.hpp"

using namespace std;
using json=nlohmann::json;
namespace beast=boost::beast;
namespace http = boost::beast::http;
namespace net=boost::asio;
namespace ssl=net::ssl;

<<<<<<< Updated upstream
struct KeyInfo{
    string id;
    RSAKeyPair keys;
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
=======
string peerAddress;
KDC control;
>>>>>>> Stashed changes
void printHex(const vector<unsigned char>& data){
    for (unsigned char byte : data) {
        printf("%02x", byte);
    }
    printf("\n");
}

//This is needed in order to actually have a sender and reciever. Might need to be shifted into the socketHandler
//Or stay here.
// void sendMessage(const std::string& recipientName, const std::string& message) {
//     // Encrypt the message
//     auto session = cryptography::initiateSession();
//     auto seshKey = cryptography::generateSessionKey();
//     auto messageAndIV = cryptography::generateMessageKeyAndIV();
//     auto cipher = cryptography::encryptMessage(seshKey, messageAndIV, message);

//     // Send the encrypted message to the server
//     ws.send(JSON.stringify({
//         type: 'message',
//         recipientName: recipientName,
//         content: cipher
//     }));
// }

//Also need this in order to have the recipient actually decrypt the message. Need y'all to figure out where these
//two go and get them ironed out.
// ws.onmessage = (event) => {
//     const data = JSON.parse(event.data);
//     if (data.type === 'message') {
//         // Decrypt the message
//         auto session = cryptography::initiateSession();
//         auto decMessage = cryptography::decryptMessage(session, data.content);

//         // Display the decrypted message
//         console.log("Decrypted Message: ", decMessage);
//     }
// };



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
<<<<<<< Updated upstream
=======
    //Initialize KDC and crypto file
>>>>>>> Stashed changes
    try{
        net::io_context ioc;
        ssl::context ctx{ssl::context::tlsv12};

<<<<<<< Updated upstream
        ctx.use_certificate_file("server.cert", ssl::context::pem);
        ctx.use_certificate_file("server.key", ssl::context::pem);
        tcp::acceptor acceptor{ioc, {tcp::v4(), 49250}};

        for(;;){
            tcp::socket socket{ioc};
            acceptor.accept(socket);
            auto ws=make_shared<WebSocketStream>(std::move(socket), ctx);
            thread{bind(&doSession, ws)}.detach();
=======
        // Load the server cert and private key
        try{

            ctx.use_certificate_file("localhost.pem", ssl::context::pem);
            ctx.use_private_key_file("localhost-key.pem", ssl::context::pem);
        }
        catch(const exception &e){
            cerr<<"Failed to load cert/key"<<endl;
        }
        
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
                cout<<"Creating SSL stream"<<endl;
                ssl::stream<tcp::socket> ssl_stream(std::move(socket), ctx);
                cout<<"Starting the handshake."<<endl;
                ssl_stream.handshake(ssl::stream_base::server);
                cout<<"Handshake completed."<<endl;
        
                // Create a WebSocket stream using the SSL stream then ensure the handshake occurs
                cout<<"Wrapping in socket stream."<<endl;
                auto ws = std::make_shared<WebSocketStream>(std::move(ssl_stream));
                beast::flat_buffer buffer;
                http::request<http::string_body> req;
                try{
                    cout<<"Reading HTTP upgrade request."<<endl;
                    http::read(*ws, buffer, req);
                    cout<<"Upgrade request received:\n."<<req<<endl;
                    ws->accept(req);
                    cout<<"webSocket accepted."<<endl;
                }
                catch(const beast::system_error &e){
                    cerr<<"WebSocket connection failed: "<<e.code().message()<<endl;
                    return;
                }
               

        
                std::thread t([ws]() {
                    try {
                        std::cout << "Starting session..." << std::endl;
                        doSession(ws, control);
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
            std::thread{handleConn, std::move(sock), std::ref(ctx)}.detach();
>>>>>>> Stashed changes
        }
    }
    catch(exception const& e){
        cerr<<"Error: "<<e.what()<<endl;
    }
<<<<<<< Updated upstream
    //Initialize KDC and crypto file
    KDC control;

    cryptography::initialize();
    while(1){
        // Placeholder data until we can retrieve user data from front end
        KeyInfo info;

        // Step 1: Generate keys
        cout << "Generating keys...\n";
        

        // Store the keys
        control.addKey(info);

        // Get peer info to set up the session
        KeyInfo retrieve;
        string recipientName;
        string peerAddress;

        try{
            recipientName=getRecipient();
            peerAddress=findIp(recipientName);
        }
        catch(const runtime_error &e){
            cout<<e.what()<<endl;
        }
        try{
            KeyInfo retrieve = control.getKey(recipientName);
        }
        catch (const runtime_error &e){
            cout << e.what() << endl;
        }
        
        

        // Get message from front end, establish a session, encrypt the message
        auto messageReceived=[peerAddress, &recipientName](const string& message){
            sendMessage();
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
        };
    }
    cryptography::cleanup();
=======
    peerAddress="";
>>>>>>> Stashed changes
    return 0;
}