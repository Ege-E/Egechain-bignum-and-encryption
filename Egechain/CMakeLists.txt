cmake_minimum_required(VERSION 4.3)
project(Egechain)

set(CMAKE_CXX_STANDARD 20)

add_executable(Egechain
        main.cpp
        Bignum.cpp
        LispParser.cpp
        Block.cpp
        LightweightCrypto.cpp
        LightweightCrypto.cpp)
