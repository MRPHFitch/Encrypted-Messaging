#ifndef SOCKET_HANDLER_HPP
#define SOCKET_HANDLER_HPP

#include <string>
#include <unordered_map>
#include <mutex>
#include <memory>
#include <boost/beast/websocket.hpp>
#include <boost/asio/ssl.hpp>
#include <boost/asio/ip/tcp.hpp>

using namespace std;
namespace websocket = boost::beast::websocket;
namespace ssl = boost::asio::ssl;
using tcp = boost::asio::ip::tcp;

extern mutex connMutex;
extern mutex recipMutex;
extern string recipientId;
extern unordered_map<string, shared_ptr<websocket::stream<ssl::stream<tcp::socket>>>> clients;

string getRecipient();
string findIp(const string& name);
shared_ptr<websocket::stream<ssl::stream<tcp::socket>>> getClientConnection(const string& name);

#endif // SOCKET_HANDLER_HPP 