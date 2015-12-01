#ifndef OAL_LDAPAUTH_H_INCLUDED
#define OAL_LDAPAUTH_H_INCLUDED

int
oal_check_cred(const oal_config_t * const config,
               const char * const username,
               const char * const password);

#endif /* OAL_LDAPAUTH_H_INCLUDED */
