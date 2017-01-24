set(CNAME "openvpn-auth-ldap")
set(VERSION 0.01)

project(${CNAME} C)
cmake_minimum_required(VERSION 2.6)

include(CTest)

option(WITH_HARDENING "Enable hardening options" ON)

if (NOT DEFINED CMAKE_INSTALL_PREFIX)
  set(CMAKE_INSTALL_PREFIX "/usr")
endif ()
# HACK: cmake >= 3.4 fixes this
if (CMAKE_INSTALL_PREFIX MATCHES "^/usr/?$")
  set(CMAKE_INSTALL_SYSCONFDIR "/etc")
  set(CMAKE_INSTALL_LOCALSTATEDIR "/var")
endif ()

include(GNUInstallDirs)

find_library(LIBLDAP NAMES "ldap")

list(APPEND CMAKE_C_FLAGS "-Wall -Wextra -pedantic")

if (WITH_HARDENING)
  set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wformat -Wformat-security -Werror=format-security" )
  set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -fstack-protector --param ssp-buffer-size=4" )
  add_definitions("-D_FORTIFY_SOURCE=2")
endif ()

message(STATUS "------------------------------------------")
message(STATUS "Build type is:        ${CMAKE_BUILD_TYPE}")
message(STATUS "Paths:")
message(STATUS "- prefix:  ${CMAKE_INSTALL_PREFIX}")
message(STATUS "- binary:  ${CMAKE_INSTALL_FULL_BINDIR}")
message(STATUS "- library: ${CMAKE_INSTALL_FULL_LIBDIR}")
message(STATUS "Libraries:")
message(STATUS "- ldap: ${LIBLDAP}")

add_subdirectory (src)
add_subdirectory (tests)
