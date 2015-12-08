#include <string.h>
#include <stdio.h>
#include <stdlib.h>

#include "config.h"
#include "ldapauth.h"

int main(int argc, char *argv[]) {
  char buf[128];
  char username[32];
  char password[32];
  oal_config_t *config;

  if (argc < 2) {
    fprintf(stderr, "Usage: %s <config>\n", argv[0]);
    return 1;
  }

  config = (oal_config_t *) calloc (1, sizeof (oal_config_t));

  if (parse_config(config, argv[1]) != 0) {
    fprintf(stderr, "config parser failed: %s\n", config->error);
    return 1;
  }

  if (check_config(config) != 0) {
    fprintf(stderr, "config check failed: %s\n", config->error);
    return 1;
  }

  while (fgets(buf, sizeof(buf), stdin) != NULL) {
    if (sscanf(buf, "%31s %31s", username, password) != 2) {
      fputs("fail: expected '<username> <password>' line\n", stdout);
      continue;
    }
    if (oal_check_cred(config, username, password) > 0) {
      fputs("ok\n", stdout);
    } else {
      fprintf(stderr, "fail: %s\n", config->error);
    }
  }

  free(config);

  return 0;
}
