cmake_minimum_required(VERSION 3.16)
project(dhtnet
    VERSION 0.0.1
    LANGUAGES CXX
    DESCRIPTION "A C++ library for NAT traversal and secure communication")

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
include(CTest)
include(GNUInstallDirs)
set (prefix ${CMAKE_INSTALL_PREFIX})
set (exec_prefix "\${prefix}")
set (libdir "${CMAKE_INSTALL_FULL_LIBDIR}")
set (includedir "${CMAKE_INSTALL_FULL_INCLUDEDIR}")
set (VERSION ${CMAKE_PROJECT_VERSION})

find_package (PkgConfig REQUIRED)

find_package(msgpack-cxx CONFIG)
if(msgpack-cxx_FOUND)
  set(MSGPACK_LIB msgpack-cxx)
else()
  find_package(msgpackc-cxx CONFIG REQUIRED NAMES msgpackc-cxx msgpack)
  set(MSGPACK_LIB msgpackc-cxx)
endif()

find_package(fmt)
pkg_check_modules (opendht REQUIRED IMPORTED_TARGET opendht>=2.6.0)
pkg_check_modules (pjproject REQUIRED IMPORTED_TARGET libpjproject)

set (CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -DMSGPACK_NO_BOOST -DMSGPACK_DISABLE_LEGACY_NIL -DMSGPACK_DISABLE_LEGACY_CONVERT")

option(BUILD_TOOLS "Build dnc" ON)
option(DHTNET_PUPNP "Enable UPnP support" ON)
option(DHTNET_NATPMP "Enable NAT-PMP support" ON)
option(DHTNET_TESTABLE "Enable API for tests" ON)

# Sources
list (APPEND dhtnet_SOURCES
    src/connectionmanager.cpp
    src/ice_transport.cpp
    src/multiplexed_socket.cpp
    src/peer_connection.cpp
    src/string_utils.cpp
    src/fileutils.cpp
    src/ip_utils.cpp
    src/security/tls_session.cpp
    src/security/certstore.cpp
    src/security/threadloop.cpp
    src/security/diffie-hellman.cpp
    src/turn/turn_cache.cpp
    src/turn/turn_transport.cpp
    src/upnp/upnp_context.cpp
    src/upnp/upnp_control.cpp
    src/upnp/protocol/mapping.cpp
    src/upnp/protocol/igd.cpp
)

list (APPEND dhtnet_HEADERS
    include/connectionmanager.h
    include/multiplexed_socket.h
    include/tls_session.h
    include/certstore.h
    include/ice_options.h
    include/ice_transport.h
    include/ice_transport_factory.h
    include/ice_socket.h
    include/fileutils.h
    include/string_utils.h
    include/ip_utils.h
    include/upnp/mapping.h
    include/upnp/upnp_context.h
    include/upnp/upnp_control.h
)

if (DHTNET_PUPNP)
    pkg_search_module (upnp IMPORTED_TARGET upnp libupnp)
    if (NOT upnp_FOUND)
        message("libupnp not found: disabling")
        set(DHTNET_PUPNP Off)
    else()
        list (APPEND dhtnet_SOURCES
            src/upnp/protocol/pupnp/pupnp.cpp
            src/upnp/protocol/pupnp/upnp_igd.cpp
        )
        set (requiresprivate "${requiresprivate} libupnp")
    endif()
endif()
if (DHTNET_NATPMP)
    pkg_search_module (natpmp IMPORTED_TARGET natpmp)
    if (NOT natpmp_FOUND)
        find_library(natpmp_LIBRARIES natpmp)
        if (NOT natpmp_LIBRARIES)
            message("NAT-PMP not found: disabling")
            set(DHTNET_NATPMP Off)
        else()
            message("NAT-PMP found: ${natpmp_LIBRARIES}")
        endif()
    endif()
    if (DHTNET_NATPMP)
        list (APPEND dhtnet_SOURCES
            src/upnp/protocol/natpmp/nat_pmp.cpp
            src/upnp/protocol/natpmp/pmp_igd.cpp
        )
        set (libsprivate "${libsprivate} ${natpmp_LIBRARIES}")
    endif()
endif()

add_library(dhtnet ${dhtnet_SOURCES})
target_link_libraries(dhtnet PUBLIC PkgConfig::opendht PkgConfig::pjproject fmt::fmt ${MSGPACK_LIB})
if (APPLE)
    target_link_libraries(dhtnet PRIVATE "-framework CoreFoundation" "-framework Security" "resolv")
endif()

target_include_directories(dhtnet PUBLIC
    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
    $<INSTALL_INTERFACE:include>
)
if (DHTNET_PUPNP)
    target_compile_definitions(dhtnet PRIVATE HAVE_LIBUPNP)
    target_link_libraries(dhtnet PRIVATE PkgConfig::upnp)
endif()
if (DHTNET_NATPMP)
    target_compile_definitions(dhtnet PRIVATE HAVE_LIBNATPMP)
    target_link_libraries(dhtnet PRIVATE ${natpmp_LIBRARIES})
endif()
if (DHTNET_TESTABLE)
    target_compile_definitions(dhtnet PUBLIC DHTNET_TESTABLE)
endif()
target_compile_definitions(dhtnet PUBLIC PJ_AUTOCONF=1)
# set_target_properties(dhtnet PROPERTIES PUBLIC_HEADER "${CMAKE_CURRENT_SOURCE_DIR}/include/${dhtnet_HEADERS}")

configure_file(dhtnet.pc.in dhtnet.pc @ONLY)

# Install targets
install(TARGETS dhtnet)
install(DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}/include/ DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}/dhtnet)
install(FILES ${CMAKE_CURRENT_BINARY_DIR}/dhtnet.pc DESTINATION ${CMAKE_INSTALL_LIBDIR}/pkgconfig)

if (BUILD_TOOLS)
    add_executable(dnc
        tools/dnc/main.cpp
        tools/dnc/dnc.cpp
        tools/common.cpp)
    target_link_libraries(dnc PRIVATE dhtnet fmt::fmt)
    target_include_directories(dnc PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/tools)
    install(TARGETS dnc RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR})

    add_executable(upnpctrl
        tools/upnp/upnpctrl.cpp)
    target_link_libraries(upnpctrl PRIVATE dhtnet fmt::fmt readline)
    target_include_directories(upnpctrl PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/tools)
    install(TARGETS upnpctrl RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR})
endif()

if (BUILD_TESTING AND NOT MSVC)
    pkg_search_module(Cppunit REQUIRED IMPORTED_TARGET cppunit)
    add_executable(tests_certstore tests/certstore.cpp)
    target_link_libraries(tests_certstore PRIVATE dhtnet fmt::fmt PkgConfig::Cppunit)
    add_test(NAME tests_certstore COMMAND tests_certstore)

    add_executable(tests_connectionManager tests/connectionManager.cpp)
    target_link_libraries(tests_connectionManager PRIVATE dhtnet fmt::fmt PkgConfig::Cppunit)
    add_test(NAME tests_connectionManager COMMAND tests_connectionManager)

    #add_executable(tests_fileutils tests/testFileutils.cpp)
    #target_link_libraries(tests_fileutils PRIVATE dhtnet fmt::fmt PkgConfig::Cppunit)
    #add_test(NAME tests_fileutils COMMAND tests_fileutils)

    #add_executable(tests_stringutils tests/testString_utils.cpp)
    #target_link_libraries(tests_stringutils PRIVATE dhtnet fmt::fmt PkgConfig::Cppunit)
    #add_test(NAME tests_stringutils COMMAND tests_stringutils)
endif()
