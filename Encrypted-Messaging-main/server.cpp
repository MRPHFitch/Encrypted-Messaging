#include <iostream>
#include <string>
#include <vector>
#include <thread>
#include <mutex>
#include <queue>
#include <condition_variable>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include "socket_handler.h"
#include "message_handler.h"
#include "crypto_handler.h"

// ... existing code ... 