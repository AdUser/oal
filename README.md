Overview
--------

This is alternative LDAP auth module for openvpn.

Runtime requirements:

* openvpn
* libldap

Build requirements:

* cmake
* openvpn headers
* libldap headers

Installation
------------

    cmake -DCMAKE_BUILD_TYPE=Release .
    make
    make test
    sudo make install

Configuration
-------------

Firstly, you need to create config file for module.
Example config:

    # this is comment
    # server(s) to connect
    bindurls ldap://127.0.0.1 ldaps://172.16.17.1
    # username for binding
    binddn cn=openvpn-auth,dc=example,dc=com
    # password for binding
    bindpass strong-password
    # timeout on bind operation
    bindtimeout 10
    # be more verbose
    debug 0
    # where to search for users
    basedn OU=users,DC=example,DC=com
    # allow only users who match this filter
    userfilter (&(objectClass=inetOrgPerson)(user=%u)(memberOf=CN=openvpn-users,CN=groups,DC=example,DC=com))

...where %u is a placeholder for username.
You may test your config with special tool, named `oal-test`.
This tool takes line with username and password separated by space(s) and says is auth successfull or not.

If everything works fine, you'll can continue.

Next you need to move this config to secure place and make sure that only root can read it.

    mv auth-ldap.conf /etc/openvpn/
    cd /etc/openvpn/
    chmod 600 auth-ldap.conf
    chown root:root auth-ldap.conf

Next, you need load your plugin in openvpn config.
Add this line to actual config:

    plugin /usr/lib/openvpn/openvpn-plugin-auth-ldap.so "/etc/openvpn/auth-ldap.conf"

... and restart oenvpn.

Notes
-----

This project is a replacement for original [openvpn-ldap-auth](https://github.com/threerings/openvpn-auth-ldap),
which written in obj-c and requires half of gnustep as deps.

This project has no goal being 1:1 compatible with original.
Also, some important features still missing (like SSL/TLS encryption).
But it's works, and can save you from installing a bunch of GNUStep bloatware.

If you want some feature or found a bug, please open an issue on github.
