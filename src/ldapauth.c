#include <assert.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/time.h>

#define LDAP_DEPRECATED 1
#include <ldap.h>

#include "config.h"

#ifndef LDAP_DEBUG_CONNS
#define LDAP_DEBUG_CONNS 0x8
#endif

/**
 * @brief  escape chars, having special meaning in ldap search filter
 * @returns >= 0 if escaped successfully, -1 on error
 */
ssize_t
oal_ldap_escape(char *dst, size_t size, const char *src)
{
  char c = '\0';
  ssize_t pos = 0;

  assert(dst != NULL);
  assert(src != NULL);
  assert(size > 0);

  while ((c = *src) != '\0') {
    if (c == '*' || c == '(' || c == ')' || c == '\\') {
      if (size > 3) {
        *dst = snprintf(dst, 3, "\\%02x", (unsigned char) c);
      } else {
        return -1;
      }
      src += 1, dst += 3, pos += 3, size -= 3;
    } else {
      *dst = *src;
      src += 1, dst += 1, pos += 1, size -= 1;
    }
    if (size == 0)
      return -1;
  }
  *dst = '\0';

  return pos;
}

/**
 * @brief  open connection to ldap server
 * @returns 0 on success, >0 on error and fills config->error
 */
int
oal_connect(LDAP ** ld,
            oal_config_t * const config,
            const char * const binddn,
            const char * const bindpass)
{
  const short int ldapver = LDAP_VERSION3;
  const short int sizelimit = 5;
  unsigned int ldapdebug = 0;
  struct timeval tv = { 30, 0 };
  int rc = 0;

  if ((rc = ldap_initialize(ld, config->bindurls)) != LDAP_SUCCESS) {
    snprintf(config->error, sizeof(config->error), "can't connect to ldap server(s): %s", strerror(errno));
    return 1;
  }

  if (config->bindtimeout)
    tv.tv_sec = config->bindtimeout;
  if (config->debug)
    ldapdebug = LDAP_DEBUG_CONNS;

  /* hardcoded options */
  if (ldap_set_option(*ld, LDAP_OPT_PROTOCOL_VERSION, &ldapver) != LDAP_OPT_SUCCESS) {
    snprintf(config->error, sizeof(config->error), "can't set ldap protocol version");
    return 1;
  }
  if (ldap_set_option(*ld, LDAP_OPT_SIZELIMIT, &sizelimit) != LDAP_OPT_SUCCESS) {
    snprintf(config->error, sizeof(config->error), "can't set max results limit");
    return 1;
  }
  if (ldap_set_option(*ld, LDAP_OPT_REFERRALS, LDAP_OPT_OFF) != LDAP_OPT_SUCCESS) {
    snprintf(config->error, sizeof(config->error), "can't set follow referrals to 'off'");
    return 1;
  }
  /* timeouts */
  if (ldap_set_option(*ld, LDAP_OPT_NETWORK_TIMEOUT, &tv) != LDAP_OPT_SUCCESS) {
    snprintf(config->error, sizeof(config->error), "can't set network timeout: %d", config->bindtimeout);
    return 1;
  }
  if (ldap_set_option(*ld, LDAP_OPT_TIMEOUT,         &tv) != LDAP_OPT_SUCCESS) {
    snprintf(config->error, sizeof(config->error), "can't set search timeout: %d", config->bindtimeout);
    return 1;
  }
  if (ldap_set_option(*ld, LDAP_OPT_DEBUG_LEVEL, &ldapdebug) != LDAP_OPT_SUCCESS) {
    snprintf(config->error, sizeof(config->error), "can't set debug level for ldap conn");
    return 1;
  }
  /* required */
  if (ldap_set_option(*ld, LDAP_OPT_DEFBASE,   config->basedn) != LDAP_OPT_SUCCESS) {
    snprintf(config->error, sizeof(config->error), "can't set searchbase: %s", config->basedn);
    return 1;
  }

  if ((rc = ldap_simple_bind_s(*ld, binddn, bindpass)) != LDAP_SUCCESS) {
    snprintf(config->error, sizeof(config->error), "can't bind to ldap server: %s", ldap_err2string(rc));
    return 1;
  }

  return 0; /* success */
}

/**
 * @brief  find user by name in ldap directory and tries to bind with given pass
 * @returns 1 if user pass the check, 0 on password mismatch and -1 on error
 */
int
oal_check_cred(oal_config_t * const config,
               const char * const username,
               const char * const password)
{
  LDAP *sld = NULL;        /* used for user search, read as 'search ldap descriptor' */
  LDAP *ald = NULL;        /* used for user search, read as 'auth ldap descriptor' */
  LDAPMessage *res = NULL; /* whole search result */
  LDAPMessage *msg = NULL; /* first message from search result */
  char *searchattr[] = { (char *) LDAP_NO_ATTRS, NULL };
  char *udn = NULL; /* DN of found user */
  int lrc = 0;      /* return code for ldap operations, read as 'ldap return code' */
  int rc = -1;      /* function return code */
  char uid[128];     /* escaped username */
  char filter[2048]; /* basic ldap filter, combined with uid */

  assert(config   != NULL);
  assert(username != NULL);
  assert(password != NULL);

  if (oal_ldap_escape(uid, sizeof(uid), username) < 0) {
    snprintf(config->error, sizeof(config->error), "can't escape username: it's too long");
    return -1;
  }

  if (snprintf(filter, sizeof(filter), config->userfilter, uid, uid) >= (int) sizeof(filter)) {
    snprintf(config->error, sizeof(config->error), "can't interpolate userfilter: lack of space");
    return -1;
  }

  if ((oal_connect(&sld, config, config->binddn, config->bindpass)) != 0)
    return -1; /* error text already set inside oal_connect() */

  /* TODO: expand searchfilter */

  lrc = ldap_search_s(sld, config->basedn, LDAP_SCOPE_SUBTREE, filter, searchattr, 1, &res);
  if (lrc != LDAP_SUCCESS) {
    snprintf(config->error, sizeof(config->error), "ldap search failed: %s", ldap_err2string(lrc));
    goto cleanup; /* TODO */
  }

  lrc = ldap_count_entries(sld, res);
  if (lrc <= 0) {
    if (lrc == 0) {
      snprintf(config->error, sizeof(config->error), "user not found");
      rc = 0;
    }
    goto cleanup;
  }

  if ((msg = ldap_first_entry(sld, res)) == NULL) {
    snprintf(config->error, sizeof(config->error), "ldap search found something, but can't get result");
    goto cleanup;
  }

  do {
    if (ldap_msgtype(msg) != LDAP_RES_SEARCH_RESULT)
      continue;

    if ((udn = ldap_get_dn(sld, msg)) == NULL || strlen(udn) == 0) {
      snprintf(config->error, sizeof(config->error), "can't get DN of found user");
      break;
    }
fprintf(stderr, "dn: %s\n", udn);

    if (oal_connect(&ald, config, udn, password) == 0) {
      rc = 1;
      ldap_unbind(ald);
      break; /* success */
    } else {
      snprintf(config->error, sizeof(config->error), "password mismatch");
      rc = 0;
      break;
    }
    ldap_memfree(udn), udn = NULL;
  } while ((msg = ldap_next_message(sld, msg)) != NULL);

  cleanup:
  if (res) ldap_msgfree(res);
  if (udn) ldap_memfree(udn);
  if (sld) ldap_unbind(sld);
  return rc;
}
