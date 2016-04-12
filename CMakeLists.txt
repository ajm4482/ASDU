cmake_minimum_required (VERSION 2.8)
project (Simple-Web-Server)
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -std=c++11 -O3 -Wall")
set(CMAKE_LINKER /usr/bin/g++-5)
set(CMAKE_CXX_COMPILER /usr/bin/g++-5)
set(CMAKE_C_COMPILER /usr/bin/gcc-5)

if("${CMAKE_CXX_COMPILER_ID}" STREQUAL "GNU")
    if (CMAKE_CXX_COMPILER_VERSION VERSION_LESS 4.8)
        message(FATAL_ERROR "GCC version >=4.8 required.")
    endif()
elseif ("${CMAKE_CXX_COMPILER_ID}" STREQUAL "Clang")
    if (CMAKE_CXX_COMPILER_VERSION VERSION_LESS 3.3)
        message(FATAL_ERROR "Clang version >=3.3 required.")
    endif()
elseif (MSVC14) #TODO: What about other MSVC versions?
else()
    message(WARNING "Your compiler (${CMAKE_CXX_COMPILER_ID}) has not been tested on this project. Only Clang and GCC has been tested. Please report any problems at the project page on GitHub.")
endif()


include_directories(.)

find_package(Threads REQUIRED)

find_package(Boost 1.54.0 COMPONENTS regex system thread coroutine context filesystem date_time REQUIRED)
include_directories(${Boost_INCLUDE_DIR})

if(APPLE)
    set(OPENSSL_ROOT_DIR "/usr/local/opt/openssl")
endif()

#TODO: add requirement for version 1.0.1g (can it be done in one line?)
find_package(OpenSSL)

if(OPENSSL_FOUND)
    include_directories(${OPENSSL_INCLUDE_DIR})
    include_directories(../anonize2)
    include_directories(../relic-darwin/include)
    include_directories(../relic/include)


    link_directories(../anonize2)
    link_directories(../relic-darwin/lib)

    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -lc++ -fomit-frame-pointer -DNDEBUG -msse2 -mfpmath=sse -march=native")

    add_executable(server_https server/server_https.cpp)
    target_link_libraries(server_https ${Boost_LIBRARIES})
    target_link_libraries(server_https ${OPENSSL_LIBRARIES})
    target_link_libraries(server_https ${CMAKE_THREAD_LIBS_INIT})
    target_link_libraries(server_https anon)
    target_link_libraries(server_https relic_s)

    add_executable(client_https client/client_https.cpp)
    target_link_libraries(client_https ${Boost_LIBRARIES})
    target_link_libraries(client_https ${OPENSSL_LIBRARIES})
    target_link_libraries(client_https ${CMAKE_THREAD_LIBS_INIT})
    target_link_libraries(client_https anon)
    target_link_libraries(client_https relic_s)


endif()

add_executable(http_examples http_examples.cpp)
target_link_libraries(http_examples ${Boost_LIBRARIES})
target_link_libraries(http_examples ${CMAKE_THREAD_LIBS_INIT})

if(MSYS) #TODO: Is MSYS true when MSVC is true?
    target_link_libraries(http_examples ws2_32 wsock32)
    target_link_libraries(server_https ws2_32 wsock32)
endif()

enable_testing()
add_subdirectory(test)
