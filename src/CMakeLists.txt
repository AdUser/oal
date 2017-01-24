add_executable("oal-test" "testutil.c" "config.c" "ldapauth.c")
target_link_libraries("oal-test" "ldap")
install(TARGETS "oal-test" RUNTIME DESTINATION "bin")

set(CMAKE_SHARED_LIBRARY_PREFIX "")
add_library("openvpn-plugin-auth-ldap" SHARED "config.c" "ldapauth.c" "plugin.c")
target_link_libraries("openvpn-plugin-auth-ldap" "ldap")
install(TARGETS "openvpn-plugin-auth-ldap" LIBRARY DESTINATION "${CMAKE_INSTALL_LIBDIR}/openvpn")
