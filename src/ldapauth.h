/* Copyright 2015-2016 Alex 'AdUser' Z (ad_user@runbox.com)
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 */
#ifndef OAL_LDAPAUTH_H
#define OAL_LDAPAUTH_H

int
oal_check_cred(const oal_config_t * const config,
               const char * const username,
               const char * const password);

#endif /* OAL_LDAPAUTH_H */
