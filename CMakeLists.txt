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
set (docdir "${CMAKE_INSTALL_FULL_DOCDIR}")
set (top_srcdir "${CMAKE_CURRENT_SOURCE_DIR}")
set (VERSION ${CMAKE_PROJECT_VERSION})

option(DHTNET_PUPNP "Enable UPnP support" ON)
option(DHTNET_NATPMP "Enable NAT-PMP support" ON)
option(DHTNET_LLHTTP "Include llhttp in compilation" OFF)
option(DHTNET_TESTABLE "Enable API for tests" ON)
option(BUILD_TOOLS "Build tools" ON)
option(BUILD_BENCHMARKS "Build benchmarks" ON)
option(BUILD_DEPENDENCIES "Build dependencies" ON)
option(DNC_SYSTEMD_UNIT_FILE_LOCATION "Where to install systemd unit file")
option(DNC_SYSTEMD "Enable dnc systemd integration" ON)
option(CODE_COVERAGE "Enable coverage reporting" OFF)
option(BUILD_EXAMPLE "Build example" ON)

# Check if testing is enabled
if(BUILD_TESTING)
  if(CODE_COVERAGE)
    if(CMAKE_CXX_COMPILER_ID MATCHES "GNU|Clang")
      # Add the flags for coverage
      add_compile_options(-fprofile-arcs -ftest-coverage --coverage -O0)
      link_libraries(--coverage)
    endif()
  endif()
endif()

if (NOT MSVC)
    # Check if there's a recent enough version of msgpack installed on the system
    find_package(msgpack 5.0.0 QUIET CONFIG NAMES msgpack msgpackc-cxx)
    if (msgpack_FOUND)
        set(MSGPACK_TARGET "msgpackc-cxx")
    else()
        find_package(msgpack 5.0.0 QUIET CONFIG NAMES msgpack-cxx)
        if (msgpack_FOUND)
            set(MSGPACK_TARGET "msgpack-cxx")
        endif()
    endif()
    # If no suitable version of msgpack was found, build the one
    # included as a submodule in the dependencies folder
    if (NOT msgpack_FOUND)
        set(DEPENDENCIES_BUILD_ARGS "--build-msgpack")
    else()
        set(DEPENDENCIES_BUILD_ARGS "")
    endif()

    set(DEPENDENCIES_PATH ${CMAKE_CURRENT_SOURCE_DIR}/dependencies/install/${TARGET})
    message("dependencies path: ${DEPENDENCIES_PATH}")
    if (BUILD_DEPENDENCIES)
        find_package(Python3 COMPONENTS Interpreter)
        execute_process(
            COMMAND ${Python3_EXECUTABLE} ${CMAKE_CURRENT_SOURCE_DIR}/dependencies/build.py ${DEPENDENCIES_BUILD_ARGS}
            WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}/dependencies
            RESULT_VARIABLE BUILD_RESULT
        )
        if (BUILD_RESULT)
            message(FATAL_ERROR "Failed to execute build.py script.")
        endif()
    endif()
    include (GNUInstallDirs)
    list(APPEND CMAKE_FIND_ROOT_PATH ${DEPENDENCIES_PATH})
    set(CMAKE_FIND_ROOT_PATH_MODE_PACKAGE BOTH)
    list(APPEND CMAKE_PREFIX_PATH ${DEPENDENCIES_PATH})
    find_package (PkgConfig REQUIRED)
    if(NOT BUILD_SHARED_LIBS)
        list(APPEND PKG_CONFIG_EXECUTABLE "--static")
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
        -D_UNICODE \
        -DNOMINMAX \
        ")
endif()

if (DNC_SYSTEMD AND BUILD_TOOLS AND NOT MSVC)
    if (NOT DEFINED DNC_SYSTEMD_UNIT_FILE_LOCATION OR NOT DNC_SYSTEMD_UNIT_FILE_LOCATION)
        execute_process(COMMAND ${PKG_CONFIG_EXECUTABLE} systemd --variable=systemdsystemunitdir
                        OUTPUT_VARIABLE SYSTEMD_UNIT_INSTALL_DIR)
        message("-- Using Systemd unit installation directory by pkg-config: " ${SYSTEMD_UNIT_INSTALL_DIR})
    else()
        message("-- Using Systemd unit installation directory requested: " ${DNC_SYSTEMD_UNIT_FILE_LOCATION})
        set(SYSTEMD_UNIT_INSTALL_DIR ${DNC_SYSTEMD_UNIT_FILE_LOCATION})
    endif()

    if (NOT DEFINED DNC_SYSTEMD_PRESET_FILE_LOCATION OR NOT DNC_SYSTEMD_PRESET_FILE_LOCATION)
        execute_process(COMMAND ${PKG_CONFIG_EXECUTABLE} systemd --variable=systemdsystempresetdir
                        OUTPUT_VARIABLE SYSTEMD_PRESET_INSTALL_DIR)
        message("-- Using Systemd preset installation directory by pkg-config: " ${SYSTEMD_PRESET_INSTALL_DIR})
    else()
        message("-- Using Systemd preset installation directory requested: " ${DNC_SYSTEMD_PRESET_FILE_LOCATION})
        set(SYSTEMD_PRESET_INSTALL_DIR ${DNC_SYSTEMD_PRESET_FILE_LOCATION})
    endif()

    configure_file (
        tools/dnc/systemd/dnc.service.in
        systemd/dnc.service
        @ONLY
    )
    file(READ ${CMAKE_CURRENT_BINARY_DIR}/systemd/dnc.service FILE_CONTENTS)
    string(REPLACE "${CMAKE_INSTALL_PREFIX}" "" FILE_CONTENTS "${FILE_CONTENTS}")
    file(WRITE ${CMAKE_CURRENT_BINARY_DIR}/systemd/dnc.service "${FILE_CONTENTS}")

    if (SYSTEMD_UNIT_INSTALL_DIR)
        string(REGEX REPLACE "[ \t\n]+" "" SYSTEMD_UNIT_INSTALL_DIR "${SYSTEMD_UNIT_INSTALL_DIR}")
        set (systemdunitdir "${SYSTEMD_UNIT_INSTALL_DIR}")
        install (FILES ${CMAKE_CURRENT_BINARY_DIR}/systemd/dnc.service DESTINATION ${systemdunitdir})

        string(REGEX REPLACE "[ \t\n]+" "" SYSTEMD_PRESET_INSTALL_DIR "${SYSTEMD_PRESET_INSTALL_DIR}")
        set (systemdpresetdir "${SYSTEMD_PRESET_INSTALL_DIR}")
        install (FILES tools/dnc/systemd/dhtnet-dnc.preset DESTINATION ${systemdpresetdir})

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
        message("libupnp found")
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
    else()
        message("NAT-PMP found")
        set(natpmp_LIBRARIES PkgConfig::natpmp)
        set (requiresprivate "${requiresprivate} natpmp")
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
if (msgpack_FOUND)
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
if (DHTNET_LLHTTP)
    target_link_libraries(dhtnet PRIVATE ${dhtnet_PRIVATELIBS} llhttp nettle)
else()
    target_link_libraries(dhtnet PRIVATE ${dhtnet_PRIVATELIBS} nettle)
endif()

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
file(READ ${CMAKE_CURRENT_BINARY_DIR}/dhtnet.pc FILE_CONTENTS)
string(REPLACE "${CMAKE_INSTALL_PREFIX}" "" FILE_CONTENTS "${FILE_CONTENTS}")
file(WRITE ${CMAKE_CURRENT_BINARY_DIR}/dhtnet.pc "${FILE_CONTENTS}")

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
    if (DHTNET_LLHTTP)
        target_link_libraries(dnc PRIVATE dhtnet fmt::fmt yaml-cpp llhttp nettle argon2)
    else()
        target_link_libraries(dnc PRIVATE dhtnet fmt::fmt yaml-cpp nettle argon2)
    endif()

    target_include_directories(dnc PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/tools)
    install(TARGETS dnc RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR})

    add_executable(dsh
        tools/dsh/main.cpp
        tools/dsh/dsh.cpp
        tools/common.cpp
        tools/dhtnet_crtmgr/dhtnet_crtmgr.cpp)

    if (DHTNET_LLHTTP)
        target_link_libraries(dsh PRIVATE dhtnet fmt::fmt yaml-cpp llhttp nettle argon2)
    else()
        target_link_libraries(dsh PRIVATE dhtnet fmt::fmt yaml-cpp nettle argon2)
    endif()

    target_include_directories(dsh PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/tools)
    install(TARGETS dsh RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR})

    # dvpn is a Linux-only tool
    if (CMAKE_SYSTEM_NAME STREQUAL "Linux")
        add_executable(dvpn
            tools/dvpn/main.cpp
            tools/dvpn/dvpn.cpp
            tools/common.cpp
            tools/dhtnet_crtmgr/dhtnet_crtmgr.cpp)

        if (DHTNET_LLHTTP)
            target_link_libraries(dvpn PRIVATE dhtnet fmt::fmt yaml-cpp llhttp nettle argon2)
        else()
            target_link_libraries(dvpn PRIVATE dhtnet fmt::fmt yaml-cpp nettle argon2)
        endif()

        target_include_directories(dvpn PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/tools)
        install(TARGETS dvpn RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR})
    endif()

    find_library(READLINE_LIBRARIES readline)
    find_path(READLINE_INCLUDE_DIR readline/readline.h)
    add_library(readline STATIC IMPORTED)
    set_target_properties(readline PROPERTIES
        IMPORTED_LOCATION "${READLINE_LIBRARIES}"
        INTERFACE_INCLUDE_DIRECTORIES "${READLINE_INCLUDE_DIR}")
    add_executable(upnpctrl
        tools/upnp/upnpctrl.cpp)

    if (DHTNET_LLHTTP)
        target_link_libraries(upnpctrl PRIVATE dhtnet fmt::fmt readline llhttp nettle argon2)
    else()
        target_link_libraries(upnpctrl PRIVATE dhtnet fmt::fmt readline nettle argon2)
    endif()

    target_include_directories(upnpctrl PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/tools)
    install(TARGETS upnpctrl RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR})

    add_executable(dhtnet-crtmgr
        tools/dhtnet_crtmgr/main.cpp
        tools/dhtnet_crtmgr/dhtnet_crtmgr.cpp)

    if (DHTNET_LLHTTP)
        target_link_libraries(dhtnet-crtmgr PRIVATE dhtnet fmt::fmt yaml-cpp llhttp nettle argon2)
    else()
        target_link_libraries(dhtnet-crtmgr PRIVATE dhtnet fmt::fmt yaml-cpp nettle argon2)
    endif()

    target_include_directories(dhtnet-crtmgr PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/tools)
    install(TARGETS dhtnet-crtmgr RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR})

    add_executable(peerDiscovery
        tools/peerdiscovery/peerDiscovery.cpp)

    if (DHTNET_LLHTTP)
        target_link_libraries(peerDiscovery PRIVATE dhtnet fmt::fmt readline llhttp nettle argon2)
    else()
        target_link_libraries(peerDiscovery PRIVATE dhtnet fmt::fmt readline nettle argon2)
    endif()

    target_include_directories(peerDiscovery PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/tools/peerdiscovery)
    install(TARGETS peerDiscovery RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR})

    install(FILES
        tools/dnc/dnc.1
        tools/dsh/dsh.1
        tools/dvpn/dvpn.1
        tools/dhtnet_crtmgr/dhtnet-crtmgr.1
    DESTINATION ${CMAKE_INSTALL_MANDIR}/man1)

    install(FILES README.md DESTINATION ${docdir})
    install(FILES tools/dnc/README.md RENAME DNC.md DESTINATION ${docdir})
    install(FILES tools/dsh/README.md RENAME DSH.md DESTINATION ${docdir})
    install(FILES tools/dvpn/README.md RENAME DVPN.md DESTINATION ${docdir})
    install(FILES tools/dhtnet_crtmgr/README.md RENAME DHTNET_CRTMGR.md DESTINATION ${docdir})
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

    add_executable(tests_ice tests/ice.cpp)
    target_link_libraries(tests_ice PRIVATE dhtnet fmt::fmt PkgConfig::Cppunit)
    add_test(NAME tests_ice COMMAND tests_ice)

    add_executable(tests_turnCache tests/turnCache.cpp)
    target_link_libraries(tests_turnCache PRIVATE dhtnet fmt::fmt PkgConfig::Cppunit)
    add_test(NAME tests_turnCache  COMMAND tests_turnCache)

    add_executable(tests_peerDiscovery tests/peerDiscovery.cpp)
    target_link_libraries(tests_peerDiscovery PRIVATE dhtnet fmt::fmt PkgConfig::Cppunit)
    add_test(NAME tests_peerDiscovery  COMMAND tests_peerDiscovery)

    #add_executable(tests_stringutils tests/testString_utils.cpp)
    #target_link_libraries(tests_stringutils PRIVATE dhtnet fmt::fmt PkgConfig::Cppunit)
    #add_test(NAME tests_stringutils COMMAND tests_stringutils)

endif()
if (BUILD_EXAMPLES AND NOT MSVC)
    add_executable(server
    example/server.cpp)
    target_link_libraries(server PRIVATE dhtnet)
    target_include_directories(server PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/example)
    install(TARGETS server RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR})

    add_executable(client
    example/client.cpp)
    target_link_libraries(client PRIVATE dhtnet)
    target_include_directories(client PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/example)
    install(TARGETS client RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR})
endif()