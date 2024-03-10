#include "arguments.h"

#ifndef ERROR_H
#define ERROR_H

#define ERROR_CODE 1
#define ERROR_STRING_LENGTH 100

void error_exit(char *error_message, Options *options);

#endif