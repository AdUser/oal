#include <assert.h>
#include <ctype.h>
#include <errno.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>

#include "config.h"

enum { bufsize = 1024 };

int parse_config(oal_config_t * const config, const char *file) {
  FILE *f;
  unsigned short linenum = 0;
  char buf[bufsize];
  char *key, *value;
  size_t valsize;

  assert(config != NULL);
  assert(file   != NULL);

  if ((f = fopen(file, "r")) == NULL) {
    snprintf(config->error, sizeof(config->error), "can't open file: %s", strerror(errno));
    return 1;
  }

  while (fgets(buf, bufsize, f)) {
    linenum++;
    /* find start of key */
    key = buf;
    while (isspace(*key))
      key++;
    if (*key == '#')
      continue; /* ignore comments */
    if (strlen(key) == 0)
      continue; /* ignore empty lines */
    if (!isalpha(*key)) {
      snprintf(config->error, sizeof(config->error), "can't parse line %d", linenum);
      return 1;
    }
    /* find start of value */
    value = key;
    while(*value && !isspace(*value))
      value++;
    if (!isspace(*value)) {
      snprintf(config->error, sizeof(config->error), "can't find value at line %d", linenum);
      return 1;
    }
    *value = '\0', value += 1;
    while (isspace(*value))
      value++;
    if (!*value) {
      snprintf(config->error, sizeof(config->error), "can't find value at line %d", linenum);
      return 1;
    }
    /* strip trailing spaces and newline */
    valsize = strnlen(value, bufsize - (value - buf));
    while (valsize && isspace(value[valsize - 1])) {
      value[valsize - 1] = '\0';
      valsize--;
    }
    /* check & copy valid keys */
    if (strncmp(key, "bindurls", 6) == 0) {
      config->bindurls = strndup(value, valsize);
    } else
    if (strncmp(key, "binddn", 6) == 0) {
      config->binddn = strndup(value, valsize);
    } else
    if (strncmp(key, "bindpass", 8) == 0) {
      config->bindpass = strndup(value, valsize);
    } else
    if (strncmp(key, "bindtimeout", 11) == 0) {
      config->bindtimeout = atoi(value);
    } else
    if (strncmp(key, "basedn", 6) == 0) {
      config->basedn = strndup(value, valsize);
    } else
    if (strncmp(key, "userfilter", 10) == 0) {
      config->userfilter = strndup(value, valsize);
    } else
    {
      snprintf(config->error, sizeof(config->error), "unknown key '%s' at line %d", key, linenum);
      return 1;
    }
  }

  return 0;
}

int check_config(oal_config_t * const config) {
  assert(config != NULL);

  if (!config->bindurls) {
    snprintf(config->error, sizeof(config->error), "'bindurls' not set in config");
    return 1;
  }
  if (!config->basedn) {
    snprintf(config->error, sizeof(config->error), "'basedn' not set in config");
    return 1;
  }
  if (!config->userfilter) {
    snprintf(config->error, sizeof(config->error), "'userfilter' not set in config");
    return 1;
  }
  if (config->binddn && !config->bindpass) {
    snprintf(config->error, sizeof(config->error), "'bindn' set, but 'bindpass' missing in config");
    return 1;
  }

  return 0;
}
