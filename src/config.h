/* Copyright 2015-2016 Alex 'AdUser' Z (ad_user@runbox.com)
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 */
#ifndef OAL_CONFIG_H
#define OAL_CONFIG_H

typedef struct {
  char   *bindurls;      /** space-separated list ldap of URIs */
  char   *binddn;        /** bind as this user before search for user */
  char   *bindpass;      /** bind with this password */
  size_t  bindtimeout;   /** bind timeout */
  char   *basedn;        /** where to search for users */
  short   debug;         /** enable ldap debug */
  char   *userfilter;    /** ldap filter for user entry */
  char    error[1024];   /** parser error */
} oal_config_t;

int oal_error(oal_config_t * const c, const char *fmt, ...)
__attribute__ ((format (printf, 2, 3)));

int parse_config(oal_config_t * const config, const char *file);
int check_config(oal_config_t * const config);

#endif /* OAL_CONFIG_H */
