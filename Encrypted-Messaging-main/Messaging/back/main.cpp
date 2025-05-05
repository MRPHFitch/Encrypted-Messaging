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
                const string& recipientName, 
                const string& message);

// Template function to send messages for both SSL and non-SSL connections
template<typename Stream>
void sendMessage(const shared_ptr<websocket::stream<Stream>>& ws, 
                const string& recipientName, 
                const string& message) {
    try {
        cout << "Processing message for " << recipientName << endl;
        
        // For now, we'll echo back the message with some mock encryption
        json response = {
            {"type", "message"},
            {"plaintext", message},
            {"ciphertext", "encrypted:" + message},  // Mock encryption for now
            {"recipient", recipientName}
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
    try {
        cout << "Accepting WebSocket connection..." << endl;
        ws->accept();
        cout << "WebSocket connection accepted" << endl;
        
        // Initialize crypto for this session
        Crypto crypto;
        auto session = crypto.generateRSAKey();
        auto initInfo = crypto.initiateSession(session.priKey);
        auto messageAndIV = crypto.generateMessageKeyAndIV(initInfo.r1);
        
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
                    cout << "Received init message from client" << endl;
                    // Send acknowledgment
                    json response = {
                        {"type", "init_ack"},
                        {"status", "connected"}
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
                    cout << "Message received for " << recipientId << ": " << content << endl;
                    
                    // Encrypt the message
                    auto encryptedData = crypto.encryptMessage(messageAndIV[1], messageAndIV[2], content);
                    
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
                    
                    // Send encrypted message back
                    json response = {
                        {"type", "message"},
                        {"plaintext", content},
                        {"ciphertext", ciphertextHex},
                        {"hmac", hmacHex},
                        {"recipient", recipientId}
                    };
                    
                    ws->text(true);
                    ws->write(net::buffer(response.dump()), ec);
                    if(ec) {
                        cerr << "Error sending message response: " << ec.message() << endl;
                        break;
                    }
                    cout << "Message response sent" << endl;
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
    cout << "Session ended" << endl;
}

int main() {
    try {
        cout << "Initializing OpenSSL..." << endl;
        OpenSSL_add_all_algorithms();
        ERR_load_crypto_strings();
        
        cout << "Creating SSL context..." << endl;
        net::io_context ioc;
        ssl::context ctx{ssl::context::tlsv12};

        // Set SSL options
        ctx.set_options(
            ssl::context::default_workarounds |
            ssl::context::no_sslv2 |
            ssl::context::no_sslv3 |
            ssl::context::single_dh_use |
            ssl::context::no_tlsv1 |
            ssl::context::no_tlsv1_1
        );

        // Set verification mode to none for development
        ctx.set_verify_mode(ssl::verify_none);

        // Set certificate and private key
        cout << "Loading certificates..." << endl;
        try {
            ctx.use_certificate_file("server.cert", ssl::context::pem);
            cout << "Certificate loaded successfully" << endl;
        } catch (const std::exception& e) {
            cerr << "Error loading certificate: " << e.what() << endl;
            return 1;
        }

        try {
            ctx.use_private_key_file("server.key", ssl::context::pem);
            cout << "Private key loaded successfully" << endl;
        } catch (const std::exception& e) {
            cerr << "Error loading private key: " << e.what() << endl;
            return 1;
        }

        // Set cipher list
        SSL_CTX_set_cipher_list(ctx.native_handle(), "HIGH:!aNULL:!MD5");
        
        // Verify the certificate
        if (!SSL_CTX_check_private_key(ctx.native_handle())) {
            cerr << "Private key does not match the certificate" << endl;
            return 1;
        }
        cout << "Certificate verification successful" << endl;

        // Set up non-SSL acceptor only
        cout << "Setting up acceptor..." << endl;
        
        // Non-SSL acceptor
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