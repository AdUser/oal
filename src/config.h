#ifndef OAL_CONFIG_H_INCLUDED
#define OAL_CONFIG_H_INCLUDED

typedef struct {
  char   *bindurls;      /** space-separated list ldap of URIs */
  char   *binddn;        /** bind as this user before search for user */
  char   *bindpass;      /** bind with this password */
  size_t  bindtimeout;   /** bind timeout */
  short   referrals;     /** if > 0 - follow referals */
  char   *basedn;        /** where to search for users */
  char   *userfilter;    /** ldap filter for user entry */
  char    error[1024];   /** parser error */
} oal_config_t;

int parse_config(oal_config_t * const config, const char *file);
int check_config(oal_config_t * const config);

#endif /* OAL_CONFIG_H_INCLUDED */
