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