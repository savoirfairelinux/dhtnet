cmake_minimum_required(VERSION 3.20)
project(dhtnet)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

find_package (PkgConfig REQUIRED)
pkg_check_modules (opendht REQUIRED IMPORTED_TARGET opendht>=2.0.0)

# Sources
list (APPEND dhtnet_SOURCES
    src/connectionmanager.cpp
)

list (APPEND dhtnet_HEADERS
    include/connectionmanager.h
)

add_library(dhtnet ${dhtnet_SOURCES})
target_link_libraries(dhtnet PUBLIC PkgConfig::opendht)
target_include_directories(dhtnet PUBLIC include)
