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
#include "crypto.hpp"
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
string recipientId;
mutex recipMutex;
RSAKeyPair session;
initiationInfo initInfo;
vector<vector<unsigned char>> messageAndIV;

class ClientManager{
public:
    void addClient(const string &id, shared_ptr<WebSocketStream> ws){
        lock_guard<mutex> lock(connMutex);
        clients[id] = ws;
        cout << "Client " << id << " added. Total clients: " << clients.size() << endl;
    }

    void removeClient(const string &id){
        lock_guard<mutex> lock(connMutex);
        clients.erase(id);
        cout << "Client " << id << " removed. Total clients: " << clients.size() << endl;
    }

    shared_ptr<WebSocketStream> getClient(const string &id){
        lock_guard<mutex> lock(connMutex);
        auto it = clients.find(id);
        if (it != clients.end())
        {
            return it->second;
        }
        return nullptr;
    }
};

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

void doSession(shared_ptr<WebSocketStream> ws) {
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
                    }
                }
            }
            catch(const std::exception& e) {
                cerr << "Error in message handling: " << e.what() << endl;
                break;
            }
        }
    }
    catch(const std::exception& e) {
        cerr << "Error in session: " << e.what() << endl;
    }
    
    // Clean up when session ends
    if (!clientId.empty()) {
        clientMan.removeClient(clientId);
    }
    cout << "Session ended" << endl;
}

string getRecipient(){
    lock_guard<mutex> lock(recipMutex);
    return recipientId;
}

shared_ptr<WebSocketStream> getClientConnection(const string& name){
    lock_guard<mutex> lock(connMutex);
    auto it = clients.find(recipientId);
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