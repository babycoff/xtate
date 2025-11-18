cmake_minimum_required(VERSION 3.20)
project(
    xtate
    LANGUAGES               C
    VERSION                 2.13.1
    DESCRIPTION             "A modular all-stack network scanner for next-generation internet surveys."
    HOMEPAGE_URL            "https://github.com/babycoff/xtate"
    )
set(PROJECT_NAME_ALL_CAPS   "XTATE")
set(PROJECT_NAME_TITLE_CASE "Xtate")
set(PROJECT_AUTHOR          "Alvin Chen")
set(PROJECT_CONTACT         "shineccy@aliyun.com")
set(PROJECT_GITHUB_URL      "https://github.com/babycoff/xtate")
set(PROJECT_ISSUES_URL      "https://github.com/babycoff/xtate/issues")
set(PROJECT_CONF_PATH       "/etc/xtate/xtate.conf")
set(PROJECT_BANNER          "God is Stateless")


option(WITH_OPENSSL        "Build with OpenSSL library"                   ON)
option(WITH_PCRE2          "Build with PCRE2 library"                     ON)
option(WITH_LIBXML2        "Build with LibXml2 library"                   ON)
option(WITH_BSON           "Build with libbson library"                   ON)
option(WITH_MONGOC         "Build with libmongoc library"                 ON)
# option(WITH_FANN           "Build with Fann library"                      ON)


# According to C99 standards while using designated initializer:
#     "Omitted fields are implicitly initialized the same as for objects
# that have static storage duration."
#
# ref: https://gcc.gnu.org/onlinedocs/gcc/Designated-Inits.html
#
# This is more efficient to got an all-zero var than memset and could got
# a partial-zero var conveniently.
set(CMAKE_C_STANDARD 99)
set(CMAKE_C_STANDARD_REQUIRED True)

# Some operations need fixed width for number types
if(NOT CMAKE_SIZEOF_VOID_P EQUAL 8)
    message(FATAL_ERROR "This project requires a 64-bit system.")
endif()

###############################################################################
# We assume that following widths of types are correct on 64-bit system.
# Check them if you are not sure.
###############################################################################

# INCLUDE (CheckTypeSize)
# CHECK_TYPE_SIZE("int" INT_SIZE)
# if(NOT INT_SIZE EQUAL 4)
#     message(FATAL_ERROR "This project requires an environment with 32-bit int type.")
# endif()

# INCLUDE (CheckTypeSize)
# CHECK_TYPE_SIZE("float" FLOAT_SIZE)
# if(NOT FLOAT_SIZE EQUAL 4)
#     message(FATAL_ERROR "This project requires an environment with 32-bit float type.")
# endif()

# CHECK_TYPE_SIZE("time_t" TIME_SIZE)
# if(NOT TIME_SIZE EQUAL 8)
#     message(FATAL_ERROR "This project requires an environment with 64-bit time_t type.")
# endif()

# CHECK_TYPE_SIZE("size_t" SIZE_SIZE)
# if(NOT SIZE_SIZE EQUAL 8)
#     message(FATAL_ERROR "This project requires an environment with 64-bit size_t type.")
# endif()

# CHECK_TYPE_SIZE("double" DOUBLE_SIZE)
# if(NOT DOUBLE_SIZE EQUAL 8)
#     message(FATAL_ERROR "This project requires an environment with 64-bit double type.")
# endif()

# Some calculations need big-endian
if(NOT CMAKE_C_BYTE_ORDER STREQUAL "LITTLE_ENDIAN")
    message(FATAL_ERROR "This project requires a little-endian byte order.")
endif()


if (NOT CMAKE_BUILD_TYPE)
    set (CMAKE_BUILD_TYPE "Release")
    message (
       STATUS "No CMAKE_BUILD_TYPE selected, defaulting to ${CMAKE_BUILD_TYPE}"
    )
endif ()

# Use Clang or GCC
if (CMAKE_C_COMPILER_ID STREQUAL "Clang" OR CMAKE_C_COMPILER_ID STREQUAL "GNU")

    set(CMAKE_C_FLAGS_DEBUG "${CMAKE_C_FLAGS_DEBUG} -Wall -O0 -ggdb -fno-pie")
    set(CMAKE_C_FLAGS_RELEASE "${CMAKE_C_FLAGS_RELEASE} -O3 -Wall -DNDEBUG")

    ######################################################################
    # Suggest to use sanitizers to find bugs with Clang in Debug on Linux.
    ######################################################################
    if (CMAKE_C_COMPILER_ID STREQUAL "Clang" AND CMAKE_SYSTEM_NAME STREQUAL "Linux")
        # set(CMAKE_C_FLAGS_DEBUG "${CMAKE_C_FLAGS_DEBUG} -fsanitize=leak")
        # set(CMAKE_C_FLAGS_DEBUG "${CMAKE_C_FLAGS_DEBUG} -fsanitize=address")
        # set(CMAKE_C_FLAGS_DEBUG "${CMAKE_C_FLAGS_DEBUG} -fsanitize=thread")
    endif()

    # low version of Clang doesn't support attributes about sanitizer
    if (CMAKE_C_COMPILER_ID STREQUAL "Clang")
        add_compile_options(-Wno-attributes)
    endif()

    # some neglectable warnings on Windows with Clang
    # you can uncomment them to see what the warnings are
    if (CMAKE_C_COMPILER_ID STREQUAL "Clang" AND CMAKE_SYSTEM_NAME STREQUAL "Windows")
        add_compile_options(-Wno-deprecated-declarations)
        add_compile_options(-Wno-incompatible-pointer-types)
        add_compile_options(-Wno-pointer-sign)
        add_compile_options(-Wno-microsoft-enum-forward-reference)
        add_compile_options(-Wno-incompatible-function-pointer-types)
    endif ()

    # set debug option
    if (CMAKE_BUILD_TYPE STREQUAL "Debug")

        # -no-pie link option is invalid for low version of gcc & clang
        if (CMAKE_C_COMPILER_ID STREQUAL "GNU")
            execute_process(COMMAND ${CMAKE_C_COMPILER} -dumpfullversion -dumpversion OUTPUT_VARIABLE GCC_VERSION)
            string(REGEX MATCHALL "[0-9]+" GCC_VERSION_COMPONENTS ${GCC_VERSION})
            list(GET GCC_VERSION_COMPONENTS 0 GCC_MAJOR)
            list(GET GCC_VERSION_COMPONENTS 1 GCC_MINOR)
            # -no-pie is invalid in low version or Windows
            if (NOT GCC_VERSION VERSION_LESS "6.5" AND CMAKE_SYSTEM_NAME STREQUAL "Linux")
                add_link_options(-no-pie)
            endif()
        endif()

        if (CMAKE_C_COMPILER_ID STREQUAL "Clang")
            execute_process(COMMAND ${CMAKE_C_COMPILER} --version OUTPUT_VARIABLE clang_full_version_string)
            string(REGEX REPLACE ".*clang version ([0-9]+\\.[0-9]+(\\.[0-9]+)?).*" "\\1" CLANG_VERSION_STRING ${clang_full_version_string})
            string(REGEX REPLACE "([0-9]+)\\.[0-9]+(\\.[0-9]+)?" "\\1" CLANG_MAJOR_VERSION ${CLANG_VERSION_STRING})
            string(REGEX REPLACE "[0-9]+\\.([0-9]+)(\\.[0-9]+)?" "\\1" CLANG_MINOR_VERSION ${CLANG_VERSION_STRING})
            # -no-pie is invalid in low version or Windows
            if (NOT CLANG_VERSION_STRING VERSION_LESS 15.0 AND CMAKE_SYSTEM_NAME STREQUAL "Linux")
                add_link_options(-no-pie)
            endif()
        endif()

        # -rdynamic is not suitable for Windows
        if (CMAKE_SYSTEM_NAME STREQUAL "Linux")
            add_link_options(-rdynamic) # for backtrace debugging
        endif ()

    endif ()

    # using sendmmsg need this GNU extension
    if (CMAKE_SYSTEM_NAME STREQUAL "Linux")
        add_definitions(-D_GNU_SOURCE) 
    endif ()

endif ()

if (${CMAKE_BUILD_TYPE} STREQUAL "Debug")
    set(exe_name "xtate_debug")
else ()
    set(exe_name "xtate")
endif ()

add_executable(${exe_name})

file(GLOB_RECURSE sources CONFIGURE_DEPENDS src/*.c src/*.h)
target_sources(${exe_name} PUBLIC ${sources})

# Unix--------------------math(libm) libdl pthread
if (CMAKE_SYSTEM_NAME STREQUAL "Linux")
    target_link_libraries(${exe_name} m)
    target_link_libraries(${exe_name} ${CMAKE_DL_LIBS})
    # target_link_libraries(${exe_name} rt)
    find_package(Threads REQUIRED)
    target_link_libraries(${exe_name} Threads::Threads)
endif ()


# Windows--------------------WSock iphlpAPI
if (CMAKE_SYSTEM_NAME STREQUAL "Windows")
    target_link_libraries(${exe_name} wsock32 ws2_32)
    target_link_libraries(${exe_name} IPHLPAPI.lib)
endif ()


# --------------------openssl
if (WITH_OPENSSL)
    # set(OPENSSL_USE_STATIC_LIBS TRUE)
    find_package(OpenSSL 1.1.1)
endif ()

if (OPENSSL_FOUND)
    #include_directories(${OPENSSL_INCLUDE_DIR})
    target_link_libraries(${exe_name} OpenSSL::Crypto OpenSSL::SSL)
else ()
    add_compile_definitions(NOT_FOUND_OPENSSL)
endif ()


# --------------------pcre2
if (WITH_PCRE2)
    # set(PCRE2_USE_STATIC_LIBS TRUE)
    find_package(PCRE2 CONFIG COMPONENTS 8BIT)
endif ()

if (PCRE2_FOUND)
    target_link_libraries(${exe_name} PCRE2::8BIT)
    if (CMAKE_SYSTEM_NAME STREQUAL "Windows")
        get_target_property(PCRE2_LIBRARY PCRE2::8BIT LOCATION)
        message(STATUS "Found PCRE2: ${PCRE2_LIBRARY}")
    endif ()
else ()
    add_compile_definitions(NOT_FOUND_PCRE2)
endif ()


# --------------------libxml2
if (WITH_LIBXML2)
    # set(LIBXML2_USE_STATIC_LIBS TRUE)
    find_package(LibXml2)
endif ()

if (LibXml2_FOUND)
    #include_directories(${LIBXML2_INCLUDE_DIR})
    target_link_libraries(${exe_name} LibXml2::LibXml2)
    if (CMAKE_SYSTEM_NAME STREQUAL "Windows")
        get_target_property(LibXml2_LIBRARY LibXml2::LibXml2 LOCATION)
        message(STATUS "Found LibXml2: ${LibXml2_LIBRARY}")
    endif ()
else ()
    add_compile_definitions(NOT_FOUND_LIBXML2)
endif ()


# --------------------libbson
if (CMAKE_SYSTEM_NAME STREQUAL "Linux")
# libbson installed from pakage managers(e.g. apt) doesn't have cmake file.
    if (WITH_BSON)
        find_library(LIBBSON_LIBRARY NAMES bson-1.0 HINTS /usr/lib /usr/local/lib)
        find_path(LIBBSON_INCLUDE_DIR bson/bson.h HINTS /usr/include/libbson-1.0 /usr/local/include/libbson-1.0)
    endif ()

    if (LIBBSON_LIBRARY AND LIBBSON_INCLUDE_DIR)
        target_include_directories(${exe_name} PRIVATE ${LIBBSON_INCLUDE_DIR})
        target_link_libraries(${exe_name} ${LIBBSON_LIBRARY})
        message(STATUS "Found libbson: ${LIBBSON_LIBRARY}")
    else ()
        add_compile_definitions(NOT_FOUND_BSON)
    endif ()
elseif (CMAKE_SYSTEM_NAME STREQUAL "Windows")
# libbson installed from vcpkg has cmake file.
    if (WITH_BSON)
        find_package(bson-1.0 1.7)
    endif ()

    if (bson-1.0_FOUND)
        target_link_libraries(${exe_name} mongo::bson_shared)
        get_target_property(LIBBSON_LIBRARY mongo::bson_shared LOCATION)
        message(STATUS "Found libbson: ${LIBBSON_LIBRARY}")
        # special requirement for MinGW
        if (MINGW)
            add_compile_definitions(__USE_MINGW_ANSI_STDIO=1)
        endif ()
    else ()
        add_compile_definitions(NOT_FOUND_BSON)
    endif ()
else ()
    add_compile_definitions(NOT_FOUND_BSON)
endif ()


# --------------------libmongoc
if (WITH_MONGOC)
    find_package (mongoc-1.0 1.7)
endif ()

if (mongoc-1.0_FOUND)
    target_link_libraries(${exe_name} mongo::mongoc_shared)
    get_target_property(MONGOC_LIBRARY mongo::mongoc_shared LOCATION)
    message(STATUS "Found libmongoc: ${MONGOC_LIBRARY}")
else ()
    add_compile_definitions(NOT_FOUND_MONGOC)
endif ()

# --------------------lua5.3
# set(LUA_USE_STATIC_LIBS TRUE)
# find_package(Lua REQUIRED)
# target_include_directories(${exe_name} PRIVATE ${LUA_INCLUDE_DIR})
# target_link_libraries(${exe_name} ${LUA_LIBRARIES})




configure_file(${CMAKE_SOURCE_DIR}/src/version.h.in ${CMAKE_SOURCE_DIR}/src/version.h @ONLY)
