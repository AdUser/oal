#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/time.h>

#define LDAP_DEPRECATED 1
#include <ldap.h>

#include "config.h"

/** shared connection, used for searching users and
 * comparing their passwords if mode set to 'compare'
 * @returns 0 on success, 1 on error
 */
LDAP *ld = NULL;

int
oal_connect(oal_config_t * const config)
{
  const short int ldapver = LDAP_VERSION3;
  const short int sizelimit = 5;
  struct timeval tv = { 30, 0 };
  int rc = 0;

  if ((rc = ldap_initialize(&ld, config->bindurls)) != LDAP_SUCCESS) {
    snprintf(config->error, sizeof(config->error), "can't connnect to ldap server(s): %s", strerror(errno));
  }

  if (config->bindtimeout)
    tv.tv_sec = config->bindtimeout;

  /* hardcoded options */
  if (ldap_set_option(ld, LDAP_OPT_PROTOCOL_VERSION, &ldapver) != LDAP_OPT_SUCCESS) {
    snprintf(config->error, sizeof(config->error), "can't set ldap protocol version");
    goto error;
  }
  if (ldap_set_option(ld, LDAP_OPT_SIZELIMIT, &sizelimit) != LDAP_OPT_SUCCESS) {
    snprintf(config->error, sizeof(config->error), "can't set max results limit");
    goto error;
  }
  /* timeouts */
  if (ldap_set_option(ld, LDAP_OPT_NETWORK_TIMEOUT, &tv) != LDAP_OPT_SUCCESS) {
    snprintf(config->error, sizeof(config->error), "can't set network timeout: %d", config->bindtimeout);
    goto error;
  }
  if (ldap_set_option(ld, LDAP_OPT_TIMEOUT,         &tv) != LDAP_OPT_SUCCESS) {
    snprintf(config->error, sizeof(config->error), "can't set search timeout: %d", config->bindtimeout);
    goto error;
  }
  /* TODO: hardcoded */
  if (ldap_set_option(ld, LDAP_OPT_REFERRALS, LDAP_OPT_OFF) != LDAP_OPT_SUCCESS) {
    snprintf(config->error, sizeof(config->error), "can't set follow referrals to 'off'");
    goto error;
  }
  /* required */
  if (ldap_set_option(ld, LDAP_OPT_DEFBASE,   config->basedn) != LDAP_OPT_SUCCESS) {
    snprintf(config->error, sizeof(config->error), "can't set searchbase: %s", config->basedn);
    goto error;
  }

  if((rc = ldap_simple_bind_s(ld, config->binddn, config->bindpass)) != LDAP_SUCCESS) {
    snprintf(config->error, sizeof(config->error), "can't bind to ldap server: %s", ldap_err2string(rc));
    goto error;
  }

  return 0; /* success */

  error:
  return 1;
}

/**
 * @returns 1 if user pass the check, 0 on password mismatch and -1 on error
 */
int
oal_check_cred(oal_config_t * const config,
               const char * const username,
               const char * const password)
{
  LDAPMessage *res = NULL; /* whole search result */
  LDAPMessage *msg = NULL; /* first message from search result */
  char *searchattr[] = { (char *) LDAP_NO_ATTRS, NULL };
  char *udn = NULL; /* DN of found user */
  int rc = 0;

  if (!ld && !oal_connect(config))
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
  return -1;
}
