#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "../src/config.h"

int main(void) {
  oal_config_t config;

  memset(&config, 0x0, sizeof(oal_config_t));

  if (parse_config(&config, "test.conf") != 0) {
    fputs(config.error, stderr);
    return 1;
  }

  assert(config.bindtimeout == 5);
  assert(config.debug == 1);
  assert(strcmp(config.bindpass,   "strong-password") == 0);
  assert(strcmp(config.bindurls,   "ldap://127.0.0.1 ldaps://172.16.17.1") == 0);
  assert(strcmp(config.binddn,     "cn=admin,dc=example,dc=com") == 0);
  assert(strcmp(config.basedn,     "ou=users,dc=example,dc=com") == 0);
  assert(strcmp(config.userfilter, "(objectClass=inetOrgPerson)") == 0);

  return 0;
}
