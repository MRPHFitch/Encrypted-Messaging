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
#include <boost/beast.hpp>
#include <boost/beast/websocket.hpp>
#include <boost/beast/websocket/ssl.hpp>
#include <unistd.h>
#include <unordered_map>
#include <mutex>
#include <functional>
#include "headers/crypto.hpp"
#include "headers/socketHandler.hpp"
#include "../json.hpp"
#include <map>

using namespace std;
using json = nlohmann::json;
namespace net = boost::asio;
namespace beast = boost::beast;
namespace websocket = beast::websocket;
namespace ssl = boost::asio::ssl;
using tcp = boost::asio::ip::tcp;

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

class ClientManager {
private:
    unordered_map<string, shared_ptr<websocket::stream<tcp::socket>>> clients;
    mutex clientsMutex;
public:
    void addClient(const string& id, shared_ptr<websocket::stream<tcp::socket>> ws) {
        lock_guard<mutex> lock(clientsMutex);
        clients[id] = ws;
        cout << "Client " << id << " added. Total clients: " << clients.size() << endl;
    }
    
    void removeClient(const string& id) {
        lock_guard<mutex> lock(clientsMutex);
        clients.erase(id);
        cout << "Client " << id << " removed. Total clients: " << clients.size() << endl;
    }
    
    shared_ptr<websocket::stream<tcp::socket>> getClient(const string& id) {
        lock_guard<mutex> lock(clientsMutex);
        auto it = clients.find(id);
        if (it != clients.end()) {
            return it->second;
        }
        return nullptr;
    }
};

ClientManager clientManager;

class IDGenerator {
private:
    int nextId = 1;
    mutex idMutex;
public:
    string generateId() {
        lock_guard<mutex> lock(idMutex);
        return "user" + to_string(nextId++);
    }
};

IDGenerator idGenerator;

void printHex(const vector<unsigned char>& data){
    for (unsigned char byte : data) {
        printf("%02x", byte);
    }
    printf("\n");
}

// Forward declarations
template<typename Stream>
void doSession(shared_ptr<websocket::stream<Stream>> ws);

template<typename Stream>
void sendMessage(const shared_ptr<websocket::stream<Stream>>& ws, 
                const string& recipientId, 
                const string& message);

// Template function to send messages for both SSL and non-SSL connections
template<typename Stream>
void sendMessage(const shared_ptr<websocket::stream<Stream>>& ws, 
                const string& recipientId, 
                const string& message) {
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

// Template function to handle both SSL and non-SSL WebSocket sessions
template<typename Stream>
void doSession(shared_ptr<websocket::stream<Stream>> ws) {
    string clientId;
    try {
        cout << "Accepting WebSocket connection..." << endl;
        ws->accept();
        cout << "WebSocket connection accepted" << endl;
        
        // Initialize crypto for this session
        Crypto crypto;
        auto session = crypto.generateRSAKey();
        auto initInfo = crypto.initiateSession(session.pubKey);
        auto messageAndIV = crypto.generateMessageKeys(initInfo.r1);
        
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
                    clientId = idGenerator.generateId();
                    cout << "Assigned ID " << clientId << " to new client" << endl;
                    clientManager.addClient(clientId, ws);
                    
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
                    string recipientId = data["recipientId"].get<string>();
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
                    auto recipientWs = clientManager.getClient(recipientId);
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
        clientManager.removeClient(clientId);
    }
    cout << "Session ended" << endl;
}

int main() {
    try {
        cout << "Setting up server..." << endl;
        net::io_context ioc;
        
        // Set up non-SSL acceptor
        cout << "Setting up acceptor..." << endl;
        tcp::acceptor ws_acceptor{ioc};
        boost::system::error_code ec;
        ws_acceptor.open(tcp::v4(), ec);
        if (ec) {
            cerr << "Error opening WS acceptor: " << ec.message() << endl;
            return 1;
        }
        ws_acceptor.set_option(tcp::acceptor::reuse_address(true));
        ws_acceptor.bind(tcp::endpoint(tcp::v4(), 8081), ec);
        if (ec) {
            cerr << "Error binding WS acceptor: " << ec.message() << endl;
            return 1;
        }
        ws_acceptor.listen(boost::asio::socket_base::max_listen_connections, ec);
        if (ec) {
            cerr << "Error listening on WS acceptor: " << ec.message() << endl;
            return 1;
        }
        cout << "Server listening on port 8081..." << endl;

        // Function to handle non-SSL connections
        auto handle_ws_connection = [](tcp::socket socket) {
            try {
                cout << "New connection from: " << socket.remote_endpoint().address().to_string() 
                     << ":" << socket.remote_endpoint().port() << endl;
                
                auto ws = make_shared<websocket::stream<tcp::socket>>(std::move(socket));
                
                thread t([ws]() {
                    try {
                        cout << "Starting session..." << endl;
                        doSession(ws);
                        cout << "Session ended" << endl;
                    } catch (const std::exception& e) {
                        cerr << "Error in session: " << e.what() << endl;
                    }
                });
                t.detach();
            } catch (const std::exception& e) {
                cerr << "Error handling connection: " << e.what() << endl;
            }
        };

        // Accept connections
        cout << "Ready to accept connections..." << endl;
        for(;;) {
            try {
                tcp::socket ws_socket{ioc};
                cout << "Waiting for connection on port 8081..." << endl;
                ws_acceptor.accept(ws_socket);
                cout << "New connection accepted" << endl;
                handle_ws_connection(std::move(ws_socket));
            } catch (const std::exception& e) {
                cerr << "Error accepting connection: " << e.what() << endl;
                continue;
            }
        }
    }
    catch(exception const& e) {
        cerr << "Fatal error: " << e.what() << endl;
        return 1;
    }

    return 0;
}