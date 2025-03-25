cmake_minimum_required(VERSION 3.10)
project(EncryptionModule)

set(CMAKE_CXX_STANDARD 17)

file(GLOB_RECURSE SOURCES "src/*.cpp")

add_executable(encryption_module ${SOURCES})

target_link_libraries(encryption_module libsodium OpenSSL Crypto++)
