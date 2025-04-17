cmake_minimum_required(VERSION 3.15)
project(p2p_encrypted_chat)

# Use C++20
set(CMAKE_CXX_STANDARD 20)

# Locate OpenSSL installed via Homebrew
set(OPENSSL_ROOT_DIR "/usr/local/opt/openssl@3")
set(OPENSSL_INCLUDE_DIR "${OPENSSL_ROOT_DIR}/include")
set(OPENSSL_LIBRARIES "${OPENSSL_ROOT_DIR}/lib")

# Find OpenSSL
find_package(OpenSSL REQUIRED)

# Add your source files here
add_executable(main
    main.cpp
    crypto.cpp
)

# Include OpenSSL headers
target_include_directories(main PRIVATE ${OPENSSL_INCLUDE_DIR})

# Link OpenSSL libraries
target_link_libraries(main PRIVATE OpenSSL::SSL OpenSSL::Crypto)
