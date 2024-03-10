#include <stdlib.h>
#include <stdio.h>

#include "arguments.h"
#include "interfaces.h"
#include "sniffer.h"


int main(int argc, char **argv) {
    // parse the arguments
    Options *options = arguments_parse(argc, argv);

    if (options->specified_interface == 0) {
        // print the interfaces if there was none specified
        interfaces_print(options);
    } else {
        // otherwise, call the sniffer itself
        sniffer(options);
    }

    free(options);
    return 0;
}