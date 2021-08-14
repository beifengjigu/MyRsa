cmake_minimum_required(VERSION 3.13)
project(rsatest)
add_executable(rsatest main.cpp myssl.h myssl.cpp)
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -std=c++11 -g -Wall -Wno-unused-variable -pthread -lssl -lm -lcrypto")