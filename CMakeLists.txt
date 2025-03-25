cmake_minimum_required(VERSION 3.10)
project(EncryptionModule)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

file(GLOB_RECURSE SOURCES "src/*.cpp")
add_executable(encryption_module ${SOURCES})

find_package(PkgConfig REQUIRED)
pkg_check_modules(Libsodium REQUIRED libsodium)
include_directories(${LIBSODIUM_INCLUDE_DIRS})

pkg_check_modules(OPENSSL REQUIRED openssl)
include_directories(${OPENSSL_INCLUDE_DIRS})

pkg_check_modules(CryptoPP REQUIRED libcrypto++)
include_directories(${CRYPTO_PP_INCLUDE_DIRS})

target_link_libraries(encryption_module
	${LIBSODIUM_LIBRARIES}
	${OPENSSL_LIBRARIES}
	${CRYPTO_PP_LIBRARIES}
)
