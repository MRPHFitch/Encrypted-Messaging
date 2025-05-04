cmake_minimum_required(VERSION 3.15)
project(p2p_encrypted_chat)

if(POLICY CMP0042)
    cmake_policy(SET CMP0042 NEW)
endif()

# Use C++20
set(CMAKE_CXX_STANDARD 20)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)
cmake_policy(SET CMP0109 NEW)

# Detect the operating system
if(APPLE)
    # macOS specific settings
    set(OPENSSL_ROOT_DIR "/usr/local/opt/openssl@3") # Adjust this path as needed
else()
    # Windows specific settings
    set(OPENSSL_ROOT_DIR "C:/Program Files/OpenSSL-Win64")
endif()

set(OPENSSL_INCLUDE_DIR "${OPENSSL_ROOT_DIR}/include")
set(OPENSSL_LIBRARIES "${OPENSSL_ROOT_DIR}/lib")

if(POLICY CMP0167)
    cmake_policy(SET CMP0167 NEW)
endif()

# Find packages
find_package(OpenSSL REQUIRED)

if(OpenSSL_FOUND)
    include_directories(${OpenSSL_INCLUDE_DIR})
    target_link_libraries(main PRIVATE OpenSSL::SSL OpenSSL::Crypto)
endif()

find_package(Boost REQUIRED COMPONENTS system)

# Add your source files here
add_executable(main
    back/main.cpp
    back/crypto.cpp
    back/socketHandler.cpp
)

# Include directories
target_include_directories(main PRIVATE 
    ${OPENSSL_INCLUDE_DIR}
    ${CMAKE_SOURCE_DIR}/back
    ${CMAKE_SOURCE_DIR}/back/headers
    ${Boost_INCLUDE_DIR}
)

# Link OpenSSL libraries
target_link_libraries(main PRIVATE 
    OpenSSL::SSL 
    OpenSSL::Crypto 
    Boost::system
)

# macOS specific linking (if needed)
if(APPLE)
    # Add any macOS specific libraries or flags here
    target_link_libraries(main PRIVATE "-framework CoreFoundation")
endif()
