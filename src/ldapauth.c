#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/time.h>

#define LDAP_DEPRECATED 1
#include <ldap.h>

#include "config.h"

/**
 * @brief  open connection to ldap server
 * @returns 1 on success, 0 on error and fills config->error
 */
int
oal_connect(LDAP * ld,
            oal_config_t * const config,
            const char * const binddn,
            const char * const bindpass)
{
  const short int ldapver = LDAP_VERSION3;
  const short int sizelimit = 5;
  struct timeval tv = { 30, 0 };
  int rc = 0;

  if ((rc = ldap_initialize(&ld, config->bindurls)) != LDAP_SUCCESS) {
    snprintf(config->error, sizeof(config->error), "can't connnect to ldap server(s): %s", strerror(errno));
    return 1;
  }

  if (config->bindtimeout)
    tv.tv_sec = config->bindtimeout;

  /* hardcoded options */
  if (ldap_set_option(ld, LDAP_OPT_PROTOCOL_VERSION, &ldapver) != LDAP_OPT_SUCCESS) {
    snprintf(config->error, sizeof(config->error), "can't set ldap protocol version");
    return 1;
  }
  if (ldap_set_option(ld, LDAP_OPT_SIZELIMIT, &sizelimit) != LDAP_OPT_SUCCESS) {
    snprintf(config->error, sizeof(config->error), "can't set max results limit");
    return 1;
  }
  /* timeouts */
  if (ldap_set_option(ld, LDAP_OPT_NETWORK_TIMEOUT, &tv) != LDAP_OPT_SUCCESS) {
    snprintf(config->error, sizeof(config->error), "can't set network timeout: %d", config->bindtimeout);
    return 1;
  }
  if (ldap_set_option(ld, LDAP_OPT_TIMEOUT,         &tv) != LDAP_OPT_SUCCESS) {
    snprintf(config->error, sizeof(config->error), "can't set search timeout: %d", config->bindtimeout);
    return 1;
  }
  /* TODO: hardcoded */
  if (ldap_set_option(ld, LDAP_OPT_REFERRALS, LDAP_OPT_OFF) != LDAP_OPT_SUCCESS) {
    snprintf(config->error, sizeof(config->error), "can't set follow referrals to 'off'");
    return 1;
  }
  /* required */
  if (ldap_set_option(ld, LDAP_OPT_DEFBASE,   config->basedn) != LDAP_OPT_SUCCESS) {
    snprintf(config->error, sizeof(config->error), "can't set searchbase: %s", config->basedn);
    return 1;
  }

  if ((rc = ldap_simple_bind_s(ld, binddn, bindpass)) != LDAP_SUCCESS) {
    snprintf(config->error, sizeof(config->error), "can't bind to ldap server: %s", ldap_err2string(rc));
    return 1;
  }

  return 0; /* success */
}

/**
 * @returns 1 if user pass the check, 0 on password mismatch and -1 on error
 */
int
oal_check_cred(oal_config_t * const config,
               const char * const username,
               const char * const password)
{
  LDAP *ld = NULL;
  LDAPMessage *res = NULL; /* whole search result */
  LDAPMessage *msg = NULL; /* first message from search result */
  char *searchattr[] = { (char *) LDAP_NO_ATTRS, NULL };
  char *udn = NULL; /* DN of found user */
  int rc = 0;

  if ((oal_connect(ld, config, config->binddn, config->bindpass)) != 0)
    return -1; /* error text already set inside oal_connect() */

  rc = ldap_search_s(ld, config->basedn, LDAP_SCOPE_SUBTREE, config->userfilter, searchattr, 1, &res);
  if (rc != LDAP_SUCCESS) {
    snprintf(config->error, sizeof(config->error), "ldap search failed: %s", ldap_err2string(rc));
    goto error; /* TODO */
  }

  if (ldap_count_messages(ld, res) <= 0) {
    ldap_msgfree(res);
    return 0; /* no such user or error */
  }

  if ((msg = ldap_first_message(ld, res)) == NULL) {
    snprintf(config->error, sizeof(config->error), "ldap search found something, but can't get result");
    goto error;
  }

  if ((udn = ldap_get_dn(ld, msg)) == NULL) {
    snprintf(config->error, sizeof(config->error), "can't get DN of found user");
    goto error;
  }

  return 1;

  error:
  if (res) ldap_msgfree(res);
  if (msg) ldap_msgfree(msg);
  if (udn) ldap_memfree(udn);
  if (ld)  ldap_unbind(ld);
  return -1;
}
