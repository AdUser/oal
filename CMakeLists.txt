set(CNAME "openvpn-auth-ldap")
set(VERSION 0.01)

project(${CNAME} C)
cmake_minimum_required(VERSION 2.6)

include(CTest)

set(CMAKE_INSTALL_PREFIX "/usr")
set(INSTALL_LIB "${CMAKE_INSTALL_PREFIX}/lib/openvpn")

list(APPEND CMAKE_C_FLAGS "-Wall -Wextra -pedantic")

message(STATUS "------------------------------------------")
message(STATUS "Build type is:        ${CMAKE_BUILD_TYPE}")
message(STATUS "")
message(STATUS "Install prefix:       ${CMAKE_INSTALL_PREFIX}")
message(STATUS "Library directory:    ${INSTALL_LIB}")

add_subdirectory (src)
add_subdirectory (tests)
