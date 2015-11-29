SET(CNAME "openvpn-auth-ldap")
SET(VERSION 0.01)

PROJECT(${CNAME} C)
CMAKE_MINIMUM_REQUIRED(VERSION 2.6)

SET(CMAKE_INSTALL_PREFIX "/usr")
SET(INSTALL_LIB "${CMAKE_INSTALL_PREFIX}/lib/openvpn")

MESSAGE (STATUS "------------------------------------------")
MESSAGE (STATUS "Build type is:        ${CMAKE_BUILD_TYPE}")
MESSAGE (STATUS "")
MESSAGE (STATUS "Install prefix:       ${CMAKE_INSTALL_PREFIX}")
MESSAGE (STATUS "Library directory:    ${INSTALL_LIB}")

ADD_SUBDIRECTORY (src)
