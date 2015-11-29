#include <ctype.h>
#include <errno.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>

#include "config.h"

int parse_config(oal_config_t * const config, const char *file) {
  FILE *f;
  enum { bufsize = 1024 };
  unsigned short linenum = 0;
  char buf[bufsize];
  char err[bufsize];
  char *key, *value;
  size_t valsize;

  if ((f = fopen(file, "r")) == NULL) {
    snprintf(err, bufsize, "can't open file: %s", strerror(errno));
    config->error = strndup(err, bufsize);
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
      snprintf(err, bufsize, "can't parse line %d", linenum);
      config->error = strdup(err);
      return 1;
    }
    /* find start of value */
    value = key;
    while(*value && !isspace(*value))
      value++;
    if (!isspace(*value)) {
      snprintf(err, bufsize, "can't find value at line %d", linenum);
      config->error = strndup(err, bufsize);
      return 1;
    }
    *value = '\0', value += 1;
    while (isspace(*value))
      value++;
    if (!*value) {
      snprintf(err, bufsize, "can't find value at line %d", linenum);
      config->error = strndup(err, bufsize);
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
    if (strncmp(key, "referrals", 9) == 0) {
      config->referrals = atoi(value);
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
