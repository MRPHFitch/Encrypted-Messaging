#ifndef SOCKET_HANDLER_HPP
#define SOCKET_HANDLER_HPP

#include <boost/beast/core.hpp>
#include <boost/beast/websocket.hpp>
#include <boost/beast/websocket/ssl.hpp>
#include <boost/asio.hpp>
#include <boost/asio/ssl.hpp>
#include <unordered_map>
#include <memory>
#include <string>
#include <vector>
#include <mutex>
#include "crypto.hpp"

using tcp = boost::asio::ip::tcp;
namespace ssl = boost::asio::ssl;
using WebSocketStream = boost::beast::websocket::stream<ssl::stream<tcp::socket>>;

extern std::unordered_map<std::string, std::shared_ptr<WebSocketStream>> clients;
extern std::mutex connMutex;
extern std::string recipientId;
extern std::mutex recipMutex;
extern RSAKeyPair session;
extern initiationInfo initInfo;
extern std::vector<std::vector<unsigned char>> messageAndIV;
extern string peerAddress;

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

extern KDC control;

class ClientManager {
public:
    void addClient(const std::string& id, std::shared_ptr<WebSocketStream> ws);
    void removeClient(const std::string& id);
    std::shared_ptr<WebSocketStream> getClient(const std::string& id);
};

extern ClientManager clientMan;

std::string getRecipient();
std::shared_ptr<WebSocketStream> getClientConnection(const std::string& name);
std::string findIp(std::string name);

void doSession(std::shared_ptr<WebSocketStream> ws, KDC& control);

#endif  // SOCKET_HANDLER_HPP
