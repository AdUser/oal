add_library("openvpn-auth-ldap" SHARED "config.c" "main.c")

install(TARGETS "openvpn-auth-ldap"
        LIBRARY DESTINATION "${INSTALL_LIB}")
