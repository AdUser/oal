#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/time.h>

#include <ldap.h>

#include "config.h"

int
check_against_ldap(oal_config_t * const config,
                  const char * const username,
                  const char * const password)
{
  enum { bufsize = 1024 };
  struct timeval tv = { 30, 0 };
  short int tmp;
  LDAP *ld = NULL;
  LDAPMessage *res   = NULL;
  LDAPMessage *entry = NULL;
  char err[bufsize];
  char *searchattr[] = { (char *) LDAP_NO_ATTRS, NULL };
  int rc;

  if ((rc = ldap_initialize(&ld, config->bindurls)) != LDAP_SUCCESS) {
    snprintf(err, bufsize, "can't connnect to ldap server(s): %s", strerror(errno));
    config->error = strndup(err, bufsize);
  }

  if (config->bindtimeout)
    tv.tv_sec = config->bindtimeout;

  /* hardcoded options */
  tmp = LDAP_VERSION3;
  if (ldap_set_option(ld, LDAP_OPT_PROTOCOL_VERSION, &tmp) != LDAP_OPT_SUCCESS) {
    snprintf(err, bufsize, "can't set ldap protocol version");
    goto error_opts;
  }
  tmp = 5;
  if (ldap_set_option(ld, LDAP_OPT_SIZELIMIT, &tmp) != LDAP_OPT_SUCCESS) {
    snprintf(err, bufsize, "can't set max results limit");
    goto error_opts;
  }
  /* timeouts */
  if (ldap_set_option(ld, LDAP_OPT_NETWORK_TIMEOUT, &tv) != LDAP_OPT_SUCCESS) {
    snprintf(err, bufsize, "can't set network timeout: %d", config->bindtimeout);
    goto error_opts;
  }
  if (ldap_set_option(ld, LDAP_OPT_TIMEOUT,         &tv) != LDAP_OPT_SUCCESS) {
    snprintf(err, bufsize, "can't set search timeout: %d", config->bindtimeout);
    goto error_opts;
  }
  /* TODO: hardcoded */
  if (ldap_set_option(ld, LDAP_OPT_REFERRALS, LDAP_OPT_OFF) != LDAP_OPT_SUCCESS) {
    snprintf(err, bufsize, "can't set follow referrals to 'off'");
    goto error_opts;
  }
  /* required */
  if (ldap_set_option(ld, LDAP_OPT_DEFBASE,   config->basedn) != LDAP_OPT_SUCCESS) {
    snprintf(err, bufsize, "can't set searchbase: %s", config->basedn);
    goto error_opts;
  }

  if((rc = ldap_simple_bind_s(ld, config->binddn, config->bindpass)) != LDAP_SUCCESS) {
    snprintf(err, bufsize, "can't bind to ldap server: %s", ldap_err2string(rc));
    goto error_opts;
  }

  rc = ldap_search_s(ld, config->basedn, LDAP_SCOPE_SUBTREE, config->userfilter, searchattr, 1, &res);
  if (rc != LDAP_SUCCESS) {
    ;
  }

  while (1) {
    if ((ldap_simple_bind_s(ld, NULL, password)) != LDAP_SUCCESS) {
    }
  }

  if (res) {
    ldap_msgfree(res);
    res = NULL;
  }

  if (ld)
    ldap_unbind(ld);

  return 0;

  error_opts:
  config->error = strndup(err, bufsize);
  return 1;
}