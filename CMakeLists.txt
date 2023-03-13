cmake_minimum_required(VERSION 3.20)
project(dhtnet)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

find_package (PkgConfig REQUIRED)
find_package(msgpack REQUIRED QUIET CONFIG NAMES msgpack msgpack-cxx)
pkg_check_modules (opendht REQUIRED IMPORTED_TARGET opendht>=2.6.0)
pkg_check_modules (pjproject REQUIRED IMPORTED_TARGET libpjproject)

set (CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -DMSGPACK_NO_BOOST -DMSGPACK_DISABLE_LEGACY_NIL -DMSGPACK_DISABLE_LEGACY_CONVERT")

# Sources
list (APPEND dhtnet_SOURCES
    src/connectionmanager.cpp
    src/ice_transport.cpp
    src/multiplexed_socket.cpp
    src/peer_connection.cpp
    src/string_utils.cpp
    src/fileutils.cpp
    src/security/tls_session.cpp
    src/security/certstore.cpp
    src/security/threadloop.cpp
)

list (APPEND dhtnet_HEADERS
    include/connectionmanager.h
    include/multiplexed_socket.h
)

add_library(dhtnet ${dhtnet_SOURCES})
target_link_libraries(dhtnet PUBLIC PkgConfig::opendht msgpack-cxx)
target_include_directories(dhtnet PUBLIC include)
target_compile_definitions(dhtnet PRIVATE
    PJ_AUTOCONF=1
)
