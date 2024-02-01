cmake_minimum_required(VERSION 3.16)
project(dhtnet
    VERSION 0.0.1
    LANGUAGES CXX
    DESCRIPTION "A C++ library for NAT traversal and secure communication")

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
include(CTest)
include(GNUInstallDirs)
include(CheckIncludeFileCXX)
set (prefix ${CMAKE_INSTALL_PREFIX})
set (exec_prefix "\${prefix}")
set (libdir "${CMAKE_INSTALL_FULL_LIBDIR}")
set (includedir "${CMAKE_INSTALL_FULL_INCLUDEDIR}")
set (bindir "${CMAKE_INSTALL_FULL_BINDIR}")
set (sysconfdir "${CMAKE_INSTALL_FULL_SYSCONFDIR}")
set (top_srcdir "${CMAKE_CURRENT_SOURCE_DIR}")
set (VERSION ${CMAKE_PROJECT_VERSION})

option(DHTNET_PUPNP "Enable UPnP support" ON)
option(DHTNET_NATPMP "Enable NAT-PMP support" ON)
option(DHTNET_TESTABLE "Enable API for tests" ON)
option(BUILD_TOOLS "Build tools" ON)
option(BUILD_BENCHMARKS "Build benchamrks" ON)
option(BUILD_DEPENDENCIES "Build dependencies" ON)
option(DNC_SYSTEMD "Enable dnc systemd integration" ON)
option (DNC_SYSTEMD_UNIT_FILE_LOCATION "Where to install systemd unit file")


if (NOT MSVC)
    set(DEPENDENCIES_PATH ${CMAKE_CURRENT_SOURCE_DIR}/dependencies/install/${TARGET})
    message("dependencies path: ${DEPENDENCIES_PATH}")
    if (BUILD_DEPENDENCIES)
        find_package(Python3 COMPONENTS Interpreter)
        execute_process(
            COMMAND ${Python3_EXECUTABLE} ${CMAKE_CURRENT_SOURCE_DIR}/dependencies/build.py
            WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}/dependencies
        )
    endif()
    include (GNUInstallDirs)
    list(APPEND CMAKE_FIND_ROOT_PATH ${DEPENDENCIES_PATH})
    set(CMAKE_FIND_ROOT_PATH_MODE_PACKAGE BOTH)
    list(APPEND CMAKE_PREFIX_PATH ${DEPENDENCIES_PATH})
    find_package (PkgConfig REQUIRED)
    if(NOT BUILD_SHARED_LIBS)
        list(APPEND PKG_CONFIG_EXECUTABLE "--static")
    endif()

    check_include_file_cxx(msgpack.hpp HAVE_MSGPACKCXX)
    if (NOT HAVE_MSGPACKCXX)
        find_package(msgpack QUIET CONFIG NAMES msgpack msgpackc-cxx)
        if (NOT msgpack_FOUND)
            find_package(msgpack REQUIRED CONFIG NAMES msgpack-cxx)
            set(MSGPACK_TARGET "msgpack-cxx")
        else()
            set(MSGPACK_TARGET "msgpackc-cxx")
        endif()
    endif()

    if (BUILD_TOOLS)
        find_package(yaml-cpp REQUIRED)
    endif()

    include_directories(${YAML_CPP_INCLUDE_DIR})
    find_package(fmt)
    pkg_search_module (opendht REQUIRED IMPORTED_TARGET opendht)
    pkg_search_module (pjproject REQUIRED IMPORTED_TARGET libpjproject)
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

if (DNC_SYSTEMD)
    if (NOT DEFINED DNC_SYSTEMD_UNIT_FILE_LOCATION OR NOT DNC_SYSTEMD_UNIT_FILE_LOCATION)
            execute_process(COMMAND ${PKG_CONFIG_EXECUTABLE} systemd --variable=systemdsystemunitdir
                            OUTPUT_VARIABLE SYSTEMD_UNIT_INSTALL_DIR)
            message("-- Using Systemd unit installation directory by pkg-config: " ${SYSTEMD_UNIT_INSTALL_DIR})
        else()
            message("-- Using Systemd unit installation directory requested: " ${DNC_SYSTEMD_UNIT_FILE_LOCATION})
            set(SYSTEMD_UNIT_INSTALL_DIR ${DNC_SYSTEMD_UNIT_FILE_LOCATION})
        endif()

        configure_file (
            tools/dnc/systemd/dnc.service.in
            systemd/dnc.service
            @ONLY
        )
        if (SYSTEMD_UNIT_INSTALL_DIR)
            string(REGEX REPLACE "[ \t\n]+" "" SYSTEMD_UNIT_INSTALL_DIR "${SYSTEMD_UNIT_INSTALL_DIR}")
            set (systemdunitdir "${SYSTEMD_UNIT_INSTALL_DIR}")
            install (FILES ${CMAKE_CURRENT_BINARY_DIR}/systemd/dnc.service DESTINATION ${systemdunitdir})
            install (FILES tools/dnc/dnc.yaml DESTINATION ${sysconfdir}/dhtnet/)
        else()
            message(WARNING "Systemd unit installation directory not found. The systemd unit won't be installed.")
    endif()
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
            set (libsprivate "${libsprivate} -lnatpmp")
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
if (NOT HAVE_MSGPACKCXX)
    target_link_libraries(dhtnet PUBLIC ${MSGPACK_TARGET})
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
        tools/common.cpp
        tools/dhtnet_crtmgr/dhtnet_crtmgr.cpp)
    target_link_libraries(dnc PRIVATE dhtnet fmt::fmt yaml-cpp)
    target_include_directories(dnc PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/tools)
    install(TARGETS dnc RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR})

    add_executable(dsh
        tools/dsh/main.cpp
        tools/dsh/dsh.cpp
        tools/common.cpp
        tools/dhtnet_crtmgr/dhtnet_crtmgr.cpp)
    target_link_libraries(dsh PRIVATE dhtnet fmt::fmt yaml-cpp)
    target_include_directories(dsh PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/tools)
    install(TARGETS dsh RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR})

    add_executable(dvpn
        tools/dvpn/main.cpp
        tools/dvpn/dvpn.cpp
        tools/common.cpp
        tools/dhtnet_crtmgr/dhtnet_crtmgr.cpp)
    target_link_libraries(dvpn PRIVATE dhtnet fmt::fmt yaml-cpp)
    target_include_directories(dvpn PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/tools)
    install(TARGETS dvpn RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR})

    find_library(READLINE_LIBRARIES readline)
    find_path(READLINE_INCLUDE_DIR readline/readline.h)
    add_library(readline STATIC IMPORTED)
    set_target_properties(readline PROPERTIES
        IMPORTED_LOCATION "${READLINE_LIBRARIES}"
        INTERFACE_INCLUDE_DIRECTORIES "${READLINE_INCLUDE_DIR}")
    add_executable(upnpctrl
        tools/upnp/upnpctrl.cpp)
    target_link_libraries(upnpctrl PRIVATE dhtnet fmt::fmt readline)
    target_include_directories(upnpctrl PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/tools)
    install(TARGETS upnpctrl RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR})

    add_executable(dhtnet-crtmgr
        tools/dhtnet_crtmgr/main.cpp
        tools/dhtnet_crtmgr/dhtnet_crtmgr.cpp)
    target_link_libraries(dhtnet-crtmgr PRIVATE dhtnet fmt::fmt)
    target_include_directories(dhtnet-crtmgr PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/tools)
    install(TARGETS dhtnet-crtmgr RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR})

    install(FILES
        tools/dnc/dnc.1
        tools/dsh/dsh.1
    DESTINATION ${CMAKE_INSTALL_MANDIR})
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