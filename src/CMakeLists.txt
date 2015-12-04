add_executable("oal-test" "testutil.c" "config.c" "ldapauth.c")
target_link_libraries("oal-test" "ldap")

add_library("openvpn-auth-ldap" SHARED "config.c" "ldapauth.c" "plugin.c")
target_link_libraries("openvpn-auth-ldap" "ldap")

install(TARGETS "openvpn-auth-ldap"
        LIBRARY DESTINATION "${INSTALL_LIB}")
