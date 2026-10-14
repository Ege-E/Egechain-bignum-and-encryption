cmake_minimum_required(VERSION 3.20)
project(Egechain)

set(CMAKE_CXX_STANDARD 20)

add_executable(Egechain
        main.cpp
        Bignum.cpp
        LispParser.cpp
        Block.cpp
        LightweightCrypto.cpp
        Node.cpp)
