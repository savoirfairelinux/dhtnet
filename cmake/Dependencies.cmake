include(FetchContent)

set(FETCHCONTENT_UPDATES_DISCONNECTED ON CACHE BOOL
    "Do not update populated dependencies during normal builds")

set(EXPECTED_LITE_OPT_BUILD_TESTS OFF CACHE BOOL "" FORCE)
FetchContent_Declare(expected-lite
    URL https://github.com/martinmoene/expected-lite/archive/refs/tags/v0.8.0.tar.gz
    URL_HASH SHA256=27649f30bd9d4fe7b193ab3eb6f78c64d0f585c24c085f340b4722b3d0b5e701
    EXCLUDE_FROM_ALL
    OVERRIDE_FIND_PACKAGE
)
FetchContent_MakeAvailable(expected-lite)

set(RESTINIO_TEST OFF CACHE BOOL "" FORCE)
set(RESTINIO_SAMPLE OFF CACHE BOOL "" FORCE)
set(RESTINIO_BENCHMARK OFF CACHE BOOL "" FORCE)
set(RESTINIO_WITH_SOBJECTIZER OFF CACHE BOOL "" FORCE)
set(RESTINIO_DEP_STANDALONE_ASIO system CACHE STRING "" FORCE)
set(RESTINIO_DEP_LLHTTP system CACHE STRING "" FORCE)
set(RESTINIO_DEP_FMT system CACHE STRING "" FORCE)
# The target is already available, so RESTinio need not find or add it again.
set(RESTINIO_DEP_EXPECTED_LITE provided CACHE STRING "" FORCE)
FetchContent_Declare(restinio
    GIT_REPOSITORY https://github.com/Stiffstream/restinio.git
    GIT_TAG e7371c7b57234aab2786a7206825bc1d8b485c0a # v0.7.9
    SOURCE_SUBDIR dev
    EXCLUDE_FROM_ALL
    OVERRIDE_FIND_PACKAGE
)
FetchContent_MakeAvailable(restinio)

set(MSGPACK_CXX11 OFF CACHE BOOL "" FORCE)
set(MSGPACK_CXX20 ON CACHE BOOL "" FORCE)
set(MSGPACK_USE_BOOST OFF CACHE BOOL "" FORCE)
set(MSGPACK_BUILD_TESTS OFF CACHE BOOL "" FORCE)
set(MSGPACK_BUILD_DOCS OFF CACHE BOOL "" FORCE)
set(MSGPACK_BUILD_EXAMPLES OFF CACHE BOOL "" FORCE)
FetchContent_Declare(msgpack
    GIT_REPOSITORY https://github.com/msgpack/msgpack-c.git
    GIT_TAG a0b2ec09da4bd823e40fa591221713951d4ec995
    EXCLUDE_FROM_ALL
    OVERRIDE_FIND_PACKAGE
)
FetchContent_MakeAvailable(msgpack)

set(BUILD_TESTING OFF CACHE BOOL "" FORCE)
set(OPENDHT_PYTHON OFF CACHE BOOL "" FORCE)
set(OPENDHT_TOOLS OFF CACHE BOOL "" FORCE)
set(OPENDHT_EXAMPLES OFF CACHE BOOL "" FORCE)
set(OPENDHT_DOCUMENTATION OFF CACHE BOOL "" FORCE)
set(OPENDHT_HTTP ON CACHE BOOL "" FORCE)
set(OPENDHT_PROXY_CLIENT ON CACHE BOOL "" FORCE)
FetchContent_Declare(opendht
    GIT_REPOSITORY https://github.com/savoirfairelinux/opendht.git
    GIT_TAG d676aef027b0d585bce719ee9e2f3ca93fa6996d # v4.3.1
    EXCLUDE_FROM_ALL
)
FetchContent_MakeAvailable(opendht)
target_include_directories(opendht PUBLIC
    "$<BUILD_INTERFACE:${opendht_SOURCE_DIR}/include>")

find_package(PkgConfig REQUIRED)
pkg_search_module(DHTNET_SYSTEM_PJPROJECT QUIET libpjproject)
if(NOT DHTNET_SYSTEM_PJPROJECT_FOUND)
    FetchContent_Declare(pjproject
        GIT_REPOSITORY https://github.com/savoirfairelinux/pjproject.git
        GIT_TAG e9c9ea658bd15db9d6c7296f2f2518a83549b3ac
    )
    FetchContent_MakeAvailable(pjproject)

    find_program(DHTNET_MAKE_EXECUTABLE NAMES gmake make REQUIRED)
    set(PJPROJECT_INSTALL_DIR "${FETCHCONTENT_BASE_DIR}/pjproject-install")
    set(PJPROJECT_PC_FILE
        "${PJPROJECT_INSTALL_DIR}/lib/pkgconfig/libpjproject.pc")

    execute_process(
        COMMAND git rev-parse HEAD
        WORKING_DIRECTORY "${pjproject_SOURCE_DIR}"
        OUTPUT_VARIABLE PJPROJECT_REVISION
        OUTPUT_STRIP_TRAILING_WHITESPACE
        ERROR_QUIET
    )
    execute_process(
        COMMAND git diff --no-ext-diff HEAD
        WORKING_DIRECTORY "${pjproject_SOURCE_DIR}"
        OUTPUT_VARIABLE PJPROJECT_LOCAL_CHANGES
        ERROR_QUIET
    )
    string(SHA256 PJPROJECT_BUILD_KEY
        "${PJPROJECT_REVISION};${PJPROJECT_LOCAL_CHANGES};${CMAKE_C_COMPILER};${CMAKE_C_COMPILER_VERSION};${CMAKE_C_FLAGS};${CMAKE_TOOLCHAIN_FILE};${CMAKE_SYSTEM_NAME};${CMAKE_SYSTEM_PROCESSOR}")
    set(PJPROJECT_STAMP "${PJPROJECT_INSTALL_DIR}/.dhtnet-build-key")
    if(EXISTS "${PJPROJECT_STAMP}")
        file(READ "${PJPROJECT_STAMP}" PJPROJECT_PREVIOUS_BUILD_KEY)
    endif()

    if(NOT EXISTS "${PJPROJECT_PC_FILE}" OR
       NOT PJPROJECT_PREVIOUS_BUILD_KEY STREQUAL PJPROJECT_BUILD_KEY)
        message(STATUS "Building bundled PJProject")
        if(EXISTS "${pjproject_SOURCE_DIR}/build.mak")
            execute_process(
                COMMAND "${DHTNET_MAKE_EXECUTABLE}" distclean
                WORKING_DIRECTORY "${pjproject_SOURCE_DIR}"
                OUTPUT_QUIET
                ERROR_QUIET
            )
        endif()
        execute_process(
            COMMAND "${pjproject_SOURCE_DIR}/configure"
                --prefix=${PJPROJECT_INSTALL_DIR}
                --disable-sound
                --enable-video
                --enable-ext-sound
                --disable-speex-aec
                --disable-g711-codec
                --disable-l16-codec
                --disable-gsm-codec
                --disable-g722-codec
                --disable-g7221-codec
                --disable-speex-codec
                --disable-ilbc-codec
                --disable-opencore-amr
                --disable-silk
                --disable-sdl
                --disable-ffmpeg
                --disable-v4l2
                --disable-openh264
                --disable-resample
                --disable-libwebrtc
                --with-gnutls=${PJPROJECT_INSTALL_DIR}
            WORKING_DIRECTORY "${pjproject_SOURCE_DIR}"
            RESULT_VARIABLE PJPROJECT_CONFIGURE_RESULT
        )
        if(PJPROJECT_CONFIGURE_RESULT)
            message(FATAL_ERROR "Failed to configure bundled PJProject")
        endif()

        include(ProcessorCount)
        ProcessorCount(PJPROJECT_JOBS)
        execute_process(
            COMMAND "${DHTNET_MAKE_EXECUTABLE}" dep
            WORKING_DIRECTORY "${pjproject_SOURCE_DIR}"
            RESULT_VARIABLE PJPROJECT_DEP_RESULT
        )
        if(PJPROJECT_DEP_RESULT)
            message(FATAL_ERROR "Failed to generate bundled PJProject dependencies")
        endif()
        execute_process(
            COMMAND "${DHTNET_MAKE_EXECUTABLE}" -j${PJPROJECT_JOBS}
            WORKING_DIRECTORY "${pjproject_SOURCE_DIR}"
            RESULT_VARIABLE PJPROJECT_BUILD_RESULT
        )
        if(PJPROJECT_BUILD_RESULT)
            message(FATAL_ERROR "Failed to compile bundled PJProject")
        endif()
        execute_process(
            COMMAND "${DHTNET_MAKE_EXECUTABLE}" install
            WORKING_DIRECTORY "${pjproject_SOURCE_DIR}"
            RESULT_VARIABLE PJPROJECT_INSTALL_RESULT
        )
        if(PJPROJECT_INSTALL_RESULT)
            message(FATAL_ERROR "Failed to install bundled PJProject")
        endif()
        file(WRITE "${PJPROJECT_STAMP}" "${PJPROJECT_BUILD_KEY}")
    endif()

    if(DEFINED ENV{PKG_CONFIG_PATH} AND NOT "$ENV{PKG_CONFIG_PATH}" STREQUAL "")
        set(ENV{PKG_CONFIG_PATH}
            "${PJPROJECT_INSTALL_DIR}/lib/pkgconfig:$ENV{PKG_CONFIG_PATH}")
    else()
        set(ENV{PKG_CONFIG_PATH} "${PJPROJECT_INSTALL_DIR}/lib/pkgconfig")
    endif()
endif()

set(BUILD_TESTING "${DHTNET_BUILD_TESTING}" CACHE BOOL "" FORCE)