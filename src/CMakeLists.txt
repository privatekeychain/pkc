cmake_minimum_required(VERSION 3.12)
project(src)

set(CMAKE_CXX_STANDARD 11)

include_directories(${PROJECT_SOURCE_DIR}/secp256k1/include
        ${PROJECT_SOURCE_DIR}/leveldb/include
        ${PROJECT_SOURCE_DIR}/univalue/include
        ${PROJECT_SOURCE_DIR}
        )


file(GLOB_RECURSE SRCS *.cpp *,h)

add_executable(src ${SRCS})

