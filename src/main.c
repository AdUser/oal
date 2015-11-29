#include <string.h>
#include <stdio.h>
#include <stdlib.h>

#include <openvpn/openvpn-plugin.h>

#include "config.h"
#include "ldapauth.h"

static const char *OAL_NAME = "openvpn-ldap-auth";

/**
 * Given an environmental variable name, search
 * the envp array for its value, returning it
 * if found or NULL otherwise.
 */
static const char *
get_env (const char *name, const char *envp[]) {
  const int namelen = strlen(name);
  const char *cp;
  short int i;

  if (!envp)
    return NULL;

  for (i = 0; envp[i]; i++) {
	  if (strncmp(envp[i], name, namelen) == 0) {
      cp = envp[i] + namelen;
	    if (*cp == '=')
	      return cp + 1;
    }
	}

  return NULL;
}

OPENVPN_EXPORT int openvpn_plugin_min_version_required_v1(void)
{
  return 3;
}

OPENVPN_EXPORT int
openvpn_plugin_open_v3 (const int v3structver,
                        struct openvpn_plugin_args_open_in const *args,
                        struct openvpn_plugin_args_open_return *ret)
{
  oal_config_t *config;

  if (v3structver != OPENVPN_PLUGINv3_STRUCTVER)
    return OPENVPN_PLUGIN_FUNC_ERROR;

  config = (oal_config_t *) calloc (1, sizeof (oal_config_t));

  if (parse_config(config, args->argv[0]) != 0) {
    args->callbacks->plugin_log(PLOG_ERR, OAL_NAME,
      "config parser failed: %s", config->error);
    return OPENVPN_PLUGIN_FUNC_ERROR;
  }

  ret->type_mask = OPENVPN_PLUGIN_MASK (OPENVPN_PLUGIN_AUTH_USER_PASS_VERIFY);
  ret->handle    = (void *) config;

  return OPENVPN_PLUGIN_FUNC_SUCCESS;
}

OPENVPN_EXPORT int
openvpn_plugin_func_v3 (const int version,
                        struct openvpn_plugin_args_func_in const *args,
                        struct openvpn_plugin_args_func_return *retptr)
{
  oal_config_t *config = (oal_config_t *) args->handle;

  /* get username/password from envp string array */
  const char *username = get_env("username", args->envp);
  const char *password = get_env("password", args->envp);

  if (args->type == OPENVPN_PLUGIN_AUTH_USER_PASS_VERIFY) {
    /* check entered username/password against what we require */
    if (check_against_ldap(config, username, password) == 0)
      return OPENVPN_PLUGIN_FUNC_SUCCESS;
  }

  return OPENVPN_PLUGIN_FUNC_ERROR;
}

OPENVPN_EXPORT void
openvpn_plugin_close_v1 (openvpn_plugin_handle_t handle)
{
  oal_config_t *config = (oal_config_t *) handle;
  free(config->bindurls);
  free(config->binddn);
  free(config->bindpass);
  free(config->basedn);
  free(config->userfilter);
  free(config->error);
  free(config);
}
