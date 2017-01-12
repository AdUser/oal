/* Copyright 2015-2016 Alex 'AdUser' Z (ad_user@runbox.com)
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 */
#include <assert.h>
#include <ctype.h>
#include <errno.h>
#include <string.h>
#include <stdio.h>
#include <stdarg.h>
#include <stdlib.h>

#include "config.h"

enum { bufsize = 1024 };

int
oal_error(oal_config_t * const c, const char *fmt, ...) {
  va_list args;
  va_start(args, fmt);
  vsnprintf(c->error, sizeof(c->error), fmt, args);
  va_end(args);
  return 1;
}

int parse_config(oal_config_t * const config, const char *file) {
  FILE *f;
  unsigned short linenum = 0;
  char buf[bufsize];
  char *key, *value;
  size_t valsize;

  assert(config != NULL);
  assert(file   != NULL);

  if ((f = fopen(file, "r")) == NULL)
    return oal_error(config, "can't open file: %s", strerror(errno));

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
    if (!isalpha(*key))
      return oal_error(config, "can't parse line %d", linenum);
    /* find start of value */
    value = key;
    while(*value && !isspace(*value))
      value++;
    if (!isspace(*value))
      return oal_error(config, "can't find value at line %d", linenum);
    *value = '\0', value += 1;
    while (isspace(*value))
      value++;
    if (!*value)
      return oal_error(config, "can't find value at line %d", linenum);
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
    if (strncmp(key, "debug", 5) == 0) {
      config->debug = !!atoi(value);
    } else
    if (strncmp(key, "basedn", 6) == 0) {
      config->basedn = strndup(value, valsize);
    } else
    if (strncmp(key, "userfilter", 10) == 0) {
      config->userfilter = strndup(value, valsize);
    } else {
      return oal_error(config, "unknown key '%s' at line %d", key, linenum);
    }
  }

  return 0;
}

int check_config(oal_config_t * const config) {
  assert(config != NULL);

  if (!config->bindurls)
    return oal_error(config, "'bindurls' not set in config");
  if (!config->basedn)
    return oal_error(config, "'basedn' not set in config");
  if (!config->userfilter)
    return oal_error(config, "'userfilter' not set in config");
  if (config->binddn && !config->bindpass)
    return oal_error(config, "'bindn' set, but 'bindpass' missing in config");

  return 0;
}
