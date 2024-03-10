#include "arguments.h"

#ifndef FILTER_H
#define FILTER_H

#define FILTER_STRING_LENGTH 300 // maximum length of the filter string
#define MAX_SUBSTRING_LENGTH 50 // maximum length of the port + TCP/UDP protocol substring

char *filter_parse(Options *options);

#endif