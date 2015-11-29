#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "../src/config.h"

#define STEAL(attr) \
  stealed = config.attr, config.attr = NULL, config.error = NULL; \
  assert(check_config(&config) > 0); \
  assert(config.error != NULL); \
  config.attr = stealed

int main(void) {
  char *stealed = NULL;
  oal_config_t config;

  memset(&config, 0x0, sizeof(oal_config_t));

  assert(parse_config(&config, "test.conf") == 0);

  STEAL(bindpass);
  STEAL(userfilter);
  STEAL(basedn);
  STEAL(bindurls);

  return 0;
}
