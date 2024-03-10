#include <stdlib.h>
#include <stdio.h>

#include "arguments.h"
#include "error.h"


// prints the error message, frees the allocated memory and exits with ERROR_CODE
void error_exit(char *error_message, Options *options) {
    if (options != NULL) {
        free(options);
    }
    fprintf(stderr, "%s\n", error_message);
    exit(ERROR_CODE);
}