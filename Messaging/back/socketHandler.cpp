#include <boost/beast/core.hpp>
#include <boost/beast/websocket.hpp>
#include <boost/beast/websocket/ssl.hpp>
#include <boost/asio.hpp>
#include <boost/asio/ssl.hpp>
#include <boost/asio/ip/tcp.hpp>
#include <iostream>
#include <string>
#include <unordered_map>
#include <mutex>
#include <memory>
<<<<<<< Updated upstream
=======
#include "crypto.hpp"
#include "socketHandler.hpp"
>>>>>>> Stashed changes
#include "../json.hpp"

namespace beast=boost::beast;
namespace websocket=beast::websocket;
namespace net=boost::asio;
namespace ssl=net::ssl;
using namespace std;
using tcp=net::ip::tcp;
using WebSocketStream=websocket::stream<ssl::stream<tcp::socket>>;
using json=nlohmann::json;

unordered_map<string, shared_ptr<WebSocketStream>> clients;
mutex connMutex;
string recipientName;
mutex recipMutex;
<<<<<<< Updated upstream


void doSession(shared_ptr<WebSocketStream> ws, const string& clientId, function<void(const string&)> messageReceived){
    try{
        ws->accept();
        beast::flat_buffer buffer;
        ws->read(buffer);
        string initMessage=beast::buffers_to_string(buffer.data());
        auto initJson=json::parse(initMessage);
        string clientId=initJson["clientId"];

        {
            lock_guard<mutex> lock(connMutex);
            clients[clientId]=ws;
        }

        for (;;){
            buffer.clear();
            ws->read(buffer);
            string message = beast::buffers_to_string(buffer.data());
            auto messageJson=json::parse(message);
            if(messageJson["type"]=="message"){
                {
                    lock_guard<mutex> lock(recipMutex);
                    recipientName=messageJson["recipientId"];
                }
                
                string content=messageJson["content"];
                messageReceived(content);
                cout << "Received a message from " << clientId<< endl;
                {
                    lock_guard<mutex> lock(connMutex);
                    auto it = clients.find(recipientName);
                    if (it != clients.end()){
                        it->second->text(true);
                        it->second->write(net::buffer(message));
=======
RSAKeyPair session;
initiationInfo initInfo;
vector<vector<unsigned char>> messageAndIV;

void ClientManager::addClient(const string &id, shared_ptr<WebSocketStream> ws){
    lock_guard<mutex> lock(connMutex);
    clients[id] = ws;
    cout << "Client " << id << " added. Total clients: " << clients.size() << endl;
}

void ClientManager::removeClient(const string &id){
    lock_guard<mutex> lock(connMutex);
    clients.erase(id);
    cout << "Client " << id << " removed. Total clients: " << clients.size() << endl;
}

shared_ptr<WebSocketStream> ClientManager::getClient(const string &id){
    lock_guard<mutex> lock(connMutex);
    auto it = clients.find(id);
    if (it != clients.end()){
        return it->second;
    }
    return nullptr;
}

ClientManager clientMan;


class IDGenerator{
private:
    int nextId = 1;
    mutex idMutex;
public:
    string generateId(){
        lock_guard<mutex> lock(idMutex);
        return "user" + to_string(nextId++);
    }
};

IDGenerator idGen;

// Forward declarations
template<typename Stream>
void doSession(shared_ptr<WebSocketStream> ws);

template<typename Stream>
void sendMessage(const shared_ptr<WebSocketStream>& ws, const string& recipientId, const string& message);

// Template function to send messages for both SSL and non-SSL connections
template<typename Stream>
void sendMessage(const shared_ptr<WebSocketStream>& ws, const string& recipientId, const string& message) {
    try {
        cout << "Processing message for " << recipientId << endl;
        
        // For now, we'll echo back the message with some mock encryption
        json response = {
            {"type", "message"},
            {"plaintext", message},
            {"ciphertext", "encrypted:" + message},  // Mock encryption for now
            {"recipient", recipientId}
        };

        cout << "Sending response back to client" << endl;
        boost::system::error_code ec;
        ws->text(true);
        ws->write(net::buffer(response.dump()), ec);
        
        if(ec) {
            cerr << "Error sending message response: " << ec.message() << endl;
            return;
        }
        
        cout << "Message sent successfully" << endl;
    }
    catch(const std::exception& e) {
        cerr << "Error in sendMessage: " << e.what() << endl;
    }
}

void doSession(shared_ptr<WebSocketStream> ws, KDC& control) {
    string clientId;
    try {
        cout << "Accepting WebSocket connection..." << endl;
        ws->accept();
        cout << "WebSocket connection accepted" << endl;
        
        // Initialize crypto for this session
        Crypto crypto;
        session=crypto.generateRSAKey();
        initInfo=crypto.initiateSession(session.pubKey);
        messageAndIV=crypto.generateMessageKeys(initInfo.r1);
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
        for(;;) {
            try {
                beast::flat_buffer buffer;
                cout << "Waiting for message..." << endl;
                boost::system::error_code ec;
                ws->read(buffer, ec);
                
                if(ec) {
                    cerr << "Error reading message: " << ec.message() << endl;
                    break;
                }
                
                string message = beast::buffers_to_string(buffer.data());
                cout << "Received message: " << message << endl;
                
                auto data = json::parse(message);
                recipientId=data["recipientId"];

                try{
                    if (!recipientId.empty()) {
                        try {
                            peerAddress = findIp(recipientId);
                        } catch (const runtime_error &e){
                            cout<<e.what()<<endl;
                        }
                    }
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
                
                if(data["type"] == "init") {
                    // Generate a unique ID for this client
                    clientId = idGen.generateId();
                    cout << "Assigned ID " << clientId << " to new client" << endl;
                    clientMan.addClient(clientId, ws);
                    
                    // Send acknowledgment with the assigned ID
                    json response = {
                        {"type", "init_ack"},
                        {"status", "connected"},
                        {"clientId", clientId}
                    };
                    ws->text(true);
                    ws->write(net::buffer(response.dump()), ec);
                    if(ec) {
                        cerr << "Error sending init_ack: " << ec.message() << endl;
                        break;
                    }
                }
                else if(data["type"] == "recipient_change") {
                    cout << "Recipient changed to: " << data["recipientId"] << endl;
                    // No response needed for recipient change
                }
                else if(data["type"] == "message") {
                    recipientId = data["recipientId"].get<string>();
                    string content = data["content"].get<string>();
                    cout << "Message from " << clientId << " to " << recipientId << ": " << content << endl;
                    
                    // Encrypt the message
                    auto encryptedData = crypto.encryptMessage(messageAndIV[1], messageAndIV[2], messageAndIV[3], content);
                    
                    // Convert ciphertext to hex string for transmission
                    stringstream ss;
                    for(unsigned char byte : encryptedData.ciphertext) {
                        ss << hex << setw(2) << setfill('0') << (int)byte;
                    }
                    string ciphertextHex = ss.str();
                    
                    // Convert HMAC to hex string
                    ss.str("");
                    ss.clear();
                    for(unsigned char byte : encryptedData.hmac) {
                        ss << hex << setw(2) << setfill('0') << (int)byte;
                    }
                    string hmacHex = ss.str();
                    
                    // Send encrypted message to recipient
                    auto recipientWs = clientMan.getClient(recipientId);
                    if (recipientWs) {
                        json response = {
                            {"type", "message"},
                            {"plaintext", content},
                            {"ciphertext", ciphertextHex},
                            {"hmac", hmacHex},
                            {"recipient", recipientId},
                            {"sender", clientId}
                        };
                        
                        recipientWs->text(true);
                        recipientWs->write(net::buffer(response.dump()), ec);
                        if(ec) {
                            cerr << "Error sending message to recipient: " << ec.message() << endl;
                        }
                        
                        // Also send confirmation to sender
                        json senderResponse = {
                            {"type", "message"},
                            {"plaintext", content},
                            {"ciphertext", ciphertextHex},
                            {"hmac", hmacHex},
                            {"recipient", recipientId},
                            {"sender", clientId}
                        };
                        
                        ws->text(true);
                        ws->write(net::buffer(senderResponse.dump()), ec);
                    } else {
                        // Send error to sender if recipient not found
                        json errorResponse = {
                            {"type", "error"},
                            {"message", "Recipient not found"}
                        };
                        ws->text(true);
                        ws->write(net::buffer(errorResponse.dump()), ec);
>>>>>>> Stashed changes
                    }
                }
            }
            else{
                cerr<<"Recipient not connected."<<endl;
            }
        }
    }
    catch(beast::system_error const& se){
        if(se.code() != websocket::error::closed){
            cerr<<"Error: "<<se.code().message()<<endl;
        }
    }
}

string getRecipient(){
    lock_guard<mutex> lock(recipMutex);
    return recipientName;
}

shared_ptr<WebSocketStream> getClientConnection(const string& name){
    lock_guard<mutex> lock(connMutex);
    auto it = clients.find(recipientName);
    if (it != clients.end()){
        return it->second;
    }
    return nullptr;
}

string findIp(string name){
    string ipAddr;
    try{
        auto it=clients.find(name);
        if(it!=clients.end()){
            shared_ptr<WebSocketStream> peerId=it->second;
            tcp::socket& socket=peerId->next_layer().next_layer();
            tcp::endpoint remoteEndpoint = socket.remote_endpoint();
            ipAddr = remoteEndpoint.address().to_string();
        }
        else{
            throw runtime_error("Client not found.");
        }
    }
    catch(const exception e){
        cerr<<"Error retrieving IP"<<e.what()<<endl;
    }
    return ipAddr;
}