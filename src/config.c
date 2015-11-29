#include <ctype.h>
#include <errno.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>

#include "config.h"

#define BUFSIZE 1024

int parse_config(oal_config_t * const config, const char *file) {
  FILE *f;
  const size_t bufsize = 1024;
  unsigned short linenum = 0;
  char buf[BUFSIZE];
  char err[BUFSIZE];
  char *key, *value;
  size_t valsize;

  if ((f = fopen(file, "r")) == NULL) {
    snprintf(err, bufsize, "can't open file: %s", strerror(errno));
    config->error = strndup(err, bufsize);
    return 1;
  }

  while (fgets(buf, BUFSIZE, f)) {
    linenum++;
    key = buf;
    while (isspace(*key))
      key++;
    if (*key == '#')
      continue; /* ignore comments */
    if (!isalpha(*key)) {
      snprintf(err, bufsize, "can't parse line %d", linenum);
      config->error = strdup(err);
      return 1;
    }
    value = key;
    while(*value && !isspace(*value))
      value++;
    if (!isspace(value)) {
      snprintf(err, bufsize, "can't find value at line %d", linenum);
      config->error = strndup(err, bufsize);
      return 1;
    }
    *value = '\0', value += 1;
    while (isspace(*value))
      value++;
    valsize = strnlen(value, bufsize - (value - buf));

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
      snprintf(err, bufsize, "unknown key '%s' at line %d", key, linenum);
      config->error = strndup(err, bufsize);
      return 1;
    }
  }

  return 0;
}