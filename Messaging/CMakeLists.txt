cmake_minimum_required(VERSION 3.15)
project(p2p_encrypted_chat)

if(POLICY CMP0042)
    cmake_policy(SET CMP0042 NEW)
endif()

#Use C++20
set(CMAKE_CXX_STANDARD 20)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)
cmake_policy(SET CMP0109 NEW)

#Locate OpenSSL installed via Homebrew
set(OPENSSL_ROOT_DIR "/usr/local/opt/openssl@3")
set(OPENSSL_INCLUDE_DIR "${OPENSSL_ROOT_DIR}/include")
set(OPENSSL_LIBRARIES "${OPENSSL_ROOT_DIR}/lib")

#Find OpenSSL
find_package(OpenSSL REQUIRED)

#Add your source files here
add_executable(main
    back/main.cpp
    back/crypto.cpp
)

#Include OpenSSL headers
target_include_directories(main PRIVATE ${OPENSSL_INCLUDE_DIR})

#Include crypto.hpp
target_include_directories(main PRIVATE ${CMAKE_SOURCE_DIR}/back/headers)

#Link OpenSSL libraries
target_link_libraries(main PRIVATE OpenSSL::SSL OpenSSL::Crypto)