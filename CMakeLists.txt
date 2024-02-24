cmake_minimum_required(VERSION 3.7)
project(WebDc)

set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

find_package(Threads REQUIRED)
find_package(OpenSSL REQUIRED)

if(OPENSSL_FOUND)
    message(STATUS "OpenSSL found: ${OPENSSL_INCLUDE_DIR}, ${OPENSSL_CRYPTO_LIBRARY}, ${OPENSSL_SSL_LIBRARY}")
    message(STATUS "OpenSSL version: ${OPENSSL_VERSION}")
else()
    message(FATAL_ERROR "OpenSSL not found")
endif()

if (${OPENSSL_VERSION} VERSION_LESS "1.0.2")
  message(FATAL_ERROR "Invalid OpenSSL version ${OPENSSL_VERSION}")
endif()

option(WITH_TESTS "Build tests" ON)

set(EXAMPLES_DIR ${CMAKE_CURRENT_BINARY_DIR}/examples)

add_library(Dc
  src/CRC32.cc
  src/Dc.cc
  src/BarePool.cc
  src/Pool.cc
  src/Sctp.cc
  src/Sdp.cc
  src/String.cc
  src/Stun.cc
  src/Crypto.cc
  src/Rng.cc
  src/Queue.cc
)

if (UNIX AND NOT APPLE)
  add_library(Host
    src/HostEpoll.cc
    src/Network.cc
    src/picohttpparser.c
  )
else ()
  message(WARNING "Unsupported platform, defaulting to null (no-op) implementation")
  add_library(Host
    HostNull.cc
  )
endif()

target_include_directories(Dc
  PUBLIC
  $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}>
  $<INSTALL_INTERFACE:include>
  PRIVATE OpenSSL::SSL
)

target_include_directories(Host
  PUBLIC
  $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}>
  $<INSTALL_INTERFACE:include>
)

target_link_libraries(Dc
  PRIVATE OpenSSL::SSL
  PRIVATE OpenSSL::Crypto
  PRIVATE Threads::Threads
)

target_link_libraries(Host Dc)

target_compile_options(Dc
  PRIVATE
  -Wall
  -fPIC
  $<$<COMPILE_LANGUAGE:CXX>:-fno-exceptions>
  $<$<COMPILE_LANGUAGE:CXX>:-fno-rtti>
)

target_compile_options(Host
  PRIVATE
  -Wall
  $<$<COMPILE_LANGUAGE:CXX>:-fno-exceptions>
  $<$<COMPILE_LANGUAGE:CXX>:-fno-rtti>
)

install(TARGETS Dc Host EXPORT Targets
  LIBRARY DESTINATION lib
  ARCHIVE DESTINATION lib
  RUNTIME DESTINATION bin
  INCLUDES DESTINATION include
  PUBLIC_HEADER DESTINATION include
)

install(FILES src/Dc.h src/Host.h DESTINATION include)

install(EXPORT Targets
  FILE Targets.cmake
  NAMESPACE Dc::
  DESTINATION lib/cmake/Dc
)

add_executable(EchoServer examples/EchoServer.c)
target_include_directories(EchoServer PUBLIC src/)
target_link_libraries(EchoServer Host)

set_target_properties(Dc Host EchoServer PROPERTIES
  CXX_STANDARD 11
  RUNTIME_OUTPUT_DIRECTORY ${EXAMPLES_DIR}
)

file(MAKE_DIRECTORY ${EXAMPLES_DIR})
file(COPY examples/client DESTINATION ${EXAMPLES_DIR})

if (WITH_TESTS)
  set(TESTS_DIR ${CMAKE_CURRENT_BINARY_DIR}/test)
  file(MAKE_DIRECTORY ${TESTS_DIR})

  add_executable(FuzzSdp test/FuzzSdp.cc)
  add_executable(FuzzSctp test/FuzzSctp.cc)
  add_executable(FuzzStun test/FuzzStun.cc)
  target_include_directories(FuzzSdp PUBLIC src/)
  target_include_directories(FuzzSctp PUBLIC src/)
  target_include_directories(FuzzStun PUBLIC src/)
  target_link_libraries(FuzzSdp Dc)
  target_link_libraries(FuzzSctp Dc)
  target_link_libraries(FuzzStun Dc)
  file(COPY test/data DESTINATION ${TESTS_DIR})
endif()
