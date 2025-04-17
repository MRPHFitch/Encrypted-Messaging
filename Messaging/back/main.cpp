/**
 * @file Messaging
 * @author Matthew Fitch
 * @version 1.0
 * @date 2025-04-16
 * Description: Functions for both Client and Server side of things. Initializes communication, uses crypto.cpp
 * to actually negotiate key, encrypt then send message, and decrypt then display message.
 * 
*/
#include "crypto.hpp"
#include <iostream>
#include <string>
#include <thread>
#include <netinet/in.h>
#include <unistd.h>

const int PORT = 5555;

void run_server();
void run_client(const std::string& host);

int main(int argc, char* argv[]) {
    if (argc == 1) {
        run_server();
    } else {
        run_client(argv[1]);
    }
    return 0;
}
