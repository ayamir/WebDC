cmake_minimum_required(VERSION 3.7)
project(WebUdp)

set(OPENSSL_INCLUDE_DIR /usr/include/openssl-1.1/)
set(OPENSSL_SSL_LIBRARY /usr/lib/openssl-1.1/libssl.so)
set(OPENSSL_CRYPTO_LIBRARY /usr/lib/openssl-1.1/libcrypto.so)

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

option(WITH_NODE "Build Node bindings" OFF)
option(WITH_TESTS "Build tests" ON)

set(EXAMPLES_DIR ${CMAKE_CURRENT_BINARY_DIR}/examples)

add_library(Wu
  src/CRC32.cc
  src/Wu.cc
  src/WuArena.cc
  src/WuPool.cc
  src/WuSctp.cc
  src/WuSdp.cc
  src/WuString.cc
  src/WuStun.cc
  src/WuCrypto.cc
  src/WuRng.cc
  src/WuQueue.cc
)

if (UNIX AND NOT APPLE)
  add_library(WuHost
    src/WuHostEpoll.cc
    src/WuNetwork.cc
    src/picohttpparser.c
  )
else ()
  message(WARNING "Unsupported platform, defaulting to null (no-op) implementation")
  add_library(WuHost
    WuHostNull.cc
  )
endif()

target_include_directories(Wu
  PUBLIC
  $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}>
  $<INSTALL_INTERFACE:include>
  PRIVATE OpenSSL::SSL
)

target_include_directories(WuHost
  PUBLIC
  $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}>
  $<INSTALL_INTERFACE:include>
)

target_link_libraries(Wu
  PRIVATE OpenSSL::SSL
  PRIVATE OpenSSL::Crypto
  PRIVATE Threads::Threads
)

target_link_libraries(WuHost Wu)

target_compile_options(Wu
  PRIVATE
  -Wall
  -fPIC
  $<$<COMPILE_LANGUAGE:CXX>:-fno-exceptions>
  $<$<COMPILE_LANGUAGE:CXX>:-fno-rtti>
)

target_compile_options(WuHost
  PRIVATE
  -Wall
  $<$<COMPILE_LANGUAGE:CXX>:-fno-exceptions>
  $<$<COMPILE_LANGUAGE:CXX>:-fno-rtti>
)

install(TARGETS Wu WuHost EXPORT WuTargets
  LIBRARY DESTINATION lib
  ARCHIVE DESTINATION lib
  RUNTIME DESTINATION bin
  INCLUDES DESTINATION include
  PUBLIC_HEADER DESTINATION include
)

install(FILES Wu.h WuHost.h DESTINATION include)

install(EXPORT WuTargets
  FILE WuTargets.cmake
  NAMESPACE Wu::
  DESTINATION lib/cmake/Wu
)

add_executable(EchoServer examples/EchoServer.c)
target_include_directories(EchoServer PUBLIC src/)
target_link_libraries(EchoServer WuHost)

set_target_properties(Wu WuHost EchoServer PROPERTIES
  CXX_STANDARD 11
  RUNTIME_OUTPUT_DIRECTORY ${EXAMPLES_DIR}
)

file(MAKE_DIRECTORY ${EXAMPLES_DIR})
file(COPY examples/client DESTINATION ${EXAMPLES_DIR})

if (WITH_NODE)
  find_program(NPM npm)

  if (NPM)
    cmake_policy(SET CMP0070 NEW)

    file (GENERATE OUTPUT binding.gyp
      INPUT ${CMAKE_CURRENT_SOURCE_DIR}/binding.gyp.in
    )

    file (GENERATE OUTPUT package.json
      INPUT ${CMAKE_CURRENT_SOURCE_DIR}/package.json
    )

    add_custom_target(node ALL
      COMMAND npm install
      COMMAND npm run configure
      COMMAND npm run build
      WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}
    )

    add_custom_command(TARGET node POST_BUILD
      COMMAND ${CMAKE_COMMAND}
        -E copy ${CMAKE_CURRENT_BINARY_DIR}/build/Release/WebUDP.node ${EXAMPLES_DIR}
    )

    add_dependencies(node Wu)

    file(COPY examples/EchoServer.js DESTINATION ${EXAMPLES_DIR})
  else()
    message(WARNING "npm not found, skipping Node bindings")
  endif()

endif()

if (WITH_TESTS)
  set(TESTS_DIR ${CMAKE_CURRENT_BINARY_DIR}/test)
  file(MAKE_DIRECTORY ${TESTS_DIR})

  add_executable(FuzzSdp test/FuzzSdp.cc)
  add_executable(FuzzSctp test/FuzzSctp.cc)
  add_executable(FuzzStun test/FuzzStun.cc)
  target_include_directories(FuzzSdp PUBLIC src/)
  target_include_directories(FuzzSctp PUBLIC src/)
  target_include_directories(FuzzStun PUBLIC src/)
  target_link_libraries(FuzzSdp Wu)
  target_link_libraries(FuzzSctp Wu)
  target_link_libraries(FuzzStun Wu)
  file(COPY test/data DESTINATION ${TESTS_DIR})
endif()
