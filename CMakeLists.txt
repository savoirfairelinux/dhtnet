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

option(DHTNET_PUPNP "Enable UPnP support" ON)
option(DHTNET_NATPMP "Enable NAT-PMP support" ON)
option(DHTNET_TESTABLE "Enable API for tests" ON)
option(BUILD_TOOLS "Build tools" ON)
option(BUILD_BENCHMARKS "Build benchamrks" ON)

if (NOT MSVC)
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
else()
    set (WIN32_DEP_DIR ${PROJECT_SOURCE_DIR}/../)
    include_directories(
        ${WIN32_DEP_DIR}/../msvc/include
        ${WIN32_DEP_DIR}/msgpack-c/include
        ${WIN32_DEP_DIR}/asio/asio/include
        ${WIN32_DEP_DIR}/fmt/include
        ${WIN32_DEP_DIR}/pjproject/pjlib/include
        ${WIN32_DEP_DIR}/pjproject/pjlib-util/include
        ${WIN32_DEP_DIR}/pjproject/pjnath/include
        ${WIN32_DEP_DIR}/opendht/include
        ${WIN32_DEP_DIR}/opendht/src/compat/msvc
        ${WIN32_DEP_DIR}/openssl/include
        ${WIN32_DEP_DIR}/restinio/dev
        ${WIN32_DEP_DIR}/http_parser
        ${WIN32_DEP_DIR}/pupnp/include
        ${WIN32_DEP_DIR}/natpmp/include
    )
    # windirent.h
    include_directories(include/compat/msvc)
endif()

if (NOT MSVC)
    set (CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} \
        -DMSGPACK_NO_BOOST \
        -DMSGPACK_DISABLE_LEGACY_NIL \
        -DMSGPACK_DISABLE_LEGACY_CONVERT")
else()
    set (CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} \
        -DGNUTLS_INTERNAL_BUILD \
        -D_USE_MATH_DEFINES \
        -D_SCL_SECURE_NO_WARNINGS \
        -D_CRT_SECURE_NO_WARNINGS \
        -D_WINSOCK_DEPRECATED_NO_WARNINGS \
        -DASIO_STANDALONE \
        -DWIN32_LEAN_AND_MEAN \
        -D_WIN32_WINNT=0x0601 \
        -DNATPMP_STATICLIB \
        -DMSGPACK_NO_BOOST \
        -DMSGPACK_DISABLE_LEGACY_NIL \
        -DMSGPACK_DISABLE_LEGACY_CONVERT \
        -DUNICODE \
        -D_UNICODE")
endif()

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

# Port mapping dependencies - add sources and libraries
if (DHTNET_PUPNP AND NOT MSVC)
    pkg_search_module (upnp IMPORTED_TARGET upnp libupnp)
    if (NOT upnp_FOUND)
        message("libupnp not found: disabling")
        set(DHTNET_PUPNP Off)
    else()
        set(upnp_LIBRARIES PkgConfig::upnp)
        set (requiresprivate "${requiresprivate} libupnp")
    endif()
endif()
if (DHTNET_NATPMP AND NOT MSVC)
    pkg_search_module (natpmp IMPORTED_TARGET natpmp)
    if (NOT natpmp_FOUND)
        find_library(natpmp_LIBRARIES natpmp)
        if (NOT natpmp_LIBRARIES)
            message("NAT-PMP not found: disabling")
            set(DHTNET_NATPMP Off)
        else()
            message("NAT-PMP found: ${natpmp_LIBRARIES}")
            set (libsprivate "${libsprivate} ${natpmp_LIBRARIES}")
        endif()
    endif()
endif()

if (DHTNET_PUPNP)
    list (APPEND dhtnet_PRIVATE_DEFS HAVE_LIBUPNP)
    list (APPEND dhtnet_SOURCES
        src/upnp/protocol/pupnp/pupnp.cpp
        src/upnp/protocol/pupnp/upnp_igd.cpp
    )
    list (APPEND dhtnet_PRIVATELIBS ${upnp_LIBRARIES})
endif()
if (DHTNET_NATPMP)
    list (APPEND dhtnet_PRIVATE_DEFS HAVE_LIBNATPMP)
    list (APPEND dhtnet_SOURCES
        src/upnp/protocol/natpmp/nat_pmp.cpp
        src/upnp/protocol/natpmp/pmp_igd.cpp
    )
    list (APPEND dhtnet_PRIVATELIBS ${natpmp_LIBRARIES})
endif()

add_library(dhtnet ${dhtnet_SOURCES})
if (NOT MSVC)
    target_link_libraries(dhtnet PUBLIC PkgConfig::opendht PkgConfig::pjproject fmt::fmt ${MSGPACK_LIB})
else()
    target_link_libraries(dhtnet PUBLIC
        ${WIN32_DEP_DIR}/../msvc/lib/libopendht.lib
        ${WIN32_DEP_DIR}/../msvc/lib/libpjproject.lib
        ${WIN32_DEP_DIR}/../msvc/lib/libfmt.lib
        ${WIN32_DEP_DIR}/../msvc/lib/libmsgpackc-cxx.lib)
endif()
if (APPLE)
    target_link_libraries(dhtnet PRIVATE "-framework CoreFoundation" "-framework Security" "resolv")
endif()

target_include_directories(dhtnet PUBLIC
    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
    $<INSTALL_INTERFACE:include>
)

target_compile_definitions(dhtnet PRIVATE ${dhtnet_PRIVATE_DEFS})
target_link_libraries(dhtnet PRIVATE ${dhtnet_PRIVATELIBS})
if (MSVC)
    target_compile_definitions(dhtnet PRIVATE
        _CRT_SECURE_NO_WARNINGS
        _WINSOCK_DEPRECATED_NO_WARNINGS
        ASIO_STANDALONE
        _WIN32_WINNT=0x0601
        MSGPACK_NO_BOOST
        MSGPACK_DISABLE_LEGACY_NIL
        MSGPACK_DISABLE_LEGACY_CONVERT
        DHTNET_STATIC
        DHTNET_STATIC_DEFINE
        DHTNET_EXPORTS
        DHTNET_BUILDING
        DHT)
    target_compile_options(dhtnet PRIVATE
        /O2; /Oi; ${DEFAULT_CXX_RUNTIME_LIBRARY}; /Gy; /MP; /Oy-; /sdl-; /W0;
        /FC; /FS; /nologo; /Zi; /wd4996; /wd4503; /wd4180; /wd4244; /wd4267;
        /Zc:__cplusplus;
        ${DEFAULT_CXX_EXCEPTION_HANDLING})
else()
    target_compile_definitions(dhtnet PUBLIC PJ_AUTOCONF=1)
endif()

if (BUILD_TESTING AND NOT MSVC)
    target_compile_definitions(dhtnet PUBLIC DHTNET_TESTABLE)
endif()

configure_file(dhtnet.pc.in dhtnet.pc @ONLY)

# Install targets
install(TARGETS dhtnet)
install(DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}/include/ DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}/dhtnet)
install(FILES ${CMAKE_CURRENT_BINARY_DIR}/dhtnet.pc DESTINATION ${CMAKE_INSTALL_LIBDIR}/pkgconfig)

if (BUILD_TOOLS AND NOT MSVC)
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

if (BUILD_BENCHMARKS)
    add_executable(bench
        tools/benchmark/main.cpp
        tools/common.cpp)
    target_link_libraries(bench PRIVATE dhtnet fmt::fmt)
    target_include_directories(bench PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/tools)
    install(TARGETS bench RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR})
endif()

if (BUILD_TESTING AND NOT MSVC)
    pkg_search_module(Cppunit REQUIRED IMPORTED_TARGET cppunit)
    add_executable(tests_certstore tests/certstore.cpp)
    target_link_libraries(tests_certstore PRIVATE dhtnet fmt::fmt PkgConfig::Cppunit)
    add_test(NAME tests_certstore COMMAND tests_certstore)

    add_executable(tests_connectionManager tests/connectionManager.cpp)
    target_link_libraries(tests_connectionManager PRIVATE dhtnet fmt::fmt PkgConfig::Cppunit)
    add_test(NAME tests_connectionManager COMMAND tests_connectionManager)

    add_executable(tests_fileutils tests/testFileutils.cpp)
    target_link_libraries(tests_fileutils PRIVATE dhtnet fmt::fmt PkgConfig::Cppunit)
    add_test(NAME tests_fileutils COMMAND tests_fileutils)

    #add_executable(tests_stringutils tests/testString_utils.cpp)
    #target_link_libraries(tests_stringutils PRIVATE dhtnet fmt::fmt PkgConfig::Cppunit)
    #add_test(NAME tests_stringutils COMMAND tests_stringutils)
endif()
