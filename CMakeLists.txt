cmake_minimum_required(VERSION 3.0)

project(openssl_test)

include(${CMAKE_BINARY_DIR}/conanbuildinfo.cmake)
conan_basic_setup()

include_directories(${CMAKE_SOURCE_DIR}/src)

set(CMAKE_CXX_STANDARD 11)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

#fpic
set(CMAKE_POSITION_INDEPENDENT_CODE ON)

aux_source_directory(${CMAKE_SOURCE_DIR}/src SRCS)
aux_source_directory(${CMAKE_SOURCE_DIR}/example SRCS)

add_executable(openssl_exec ${SRCS})
target_link_libraries(openssl_exec ${CONAN_LIBS})
