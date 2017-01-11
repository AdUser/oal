set(CNAME "openvpn-auth-ldap")
set(VERSION 0.01)

project(${CNAME} C)
cmake_minimum_required(VERSION 2.6)

include(CTest)

option(WITH_HARDENING "Enable hardening options" ON)

if (NOT DEFINED CMAKE_INSTALL_PREFIX)
  set(CMAKE_INSTALL_PREFIX "/usr")
endif ()
set(INSTALL_LIB "${CMAKE_INSTALL_PREFIX}/lib/openvpn")

list(APPEND CMAKE_C_FLAGS "-Wall -Wextra -pedantic")

find_library(LIBLDAP NAMES "ldap")

if (WITH_HARDENING)
  set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wformat -Wformat-security -Werror=format-security" )
  set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -fstack-protector --param ssp-buffer-size=4" )
  add_definitions("-D_FORTIFY_SOURCE=2")
endif ()

message(STATUS "------------------------------------------")
message(STATUS "Build type is:        ${CMAKE_BUILD_TYPE}")
message(STATUS "")
message(STATUS "Install prefix:       ${CMAKE_INSTALL_PREFIX}")
message(STATUS "Library directory:    ${INSTALL_LIB}")
message(STATUS "")
message(STATUS "ldap:                 ${LIBLDAP}")

add_subdirectory (src)
add_subdirectory (tests)
