#include <string.h>
#include <stdio.h>
#include <stdlib.h>

#include <openvpn/openvpn-plugin.h>

#include "config.h"

int main(void) {
  oal_config_t config;
  memset(&config, 0x0, sizeof(oal_config_t));

  if (!parse_config(&config, "test.conf")) {
    fprintf(stderr, "config parser failed: %s\n", config.error);
    exit(1);
  }

  return 0;
}
