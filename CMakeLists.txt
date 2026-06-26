cmake_minimum_required(VERSION 3.16)

project(VaultX VERSION 1.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

find_package(OpenSSL REQUIRED)
find_package(SQLite3 REQUIRED)

include_directories(include)

add_executable(VaultX
    src/main.cpp
    src/Crypto.cpp
    src/Database.cpp
    src/PasswordManager.cpp
)

target_link_libraries(VaultX
    OpenSSL::SSL
    OpenSSL::Crypto
    SQLite3::SQLite3
)