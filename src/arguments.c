#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include "error.h"
#include "arguments.h"


// function for finding out whether the Options contains the given protocol
int contains_protocol(Options *options, enum Protocols protocol) {
    int i = 0;
    while (options->protocols[i] != protocol) {
        if (options->protocols[i++] == '\0') {
            return 0;
        }
    }
    return 1;
}

// function for adding a network protocol into the given Options
void add_protocol(Options *options, enum Protocols protocol) {
    if (!contains_protocol(options, protocol)) {
        int i = 0;
        while(options->protocols[i++] != '\0'); // get i to the last element in the array
        if (i <= MAX_PROTOCOLS) {
            options->protocols[i - 1] = protocol;
            options->protocols[i] = '\0';
        } else {
            error_exit("Reached the maximum number of protocols you can specify!", options);
        }
    } else {
        error_exit("You cannot specify the same protocol twice!", options);
    }
}

// function for parsing the program arguments
Options *arguments_parse(int argc, char **argv) {
    // print help message
    if (argc == 2 && strcmp(argv[1], "--help") == 0) {
        printf("Usage: ./ipk-sniffer [-i interface | --interface interface] {-p port [--tcp|-t] [--udp|-u]} [--arp] [--icmp4] [--icmp6] [--igmp] [--mld] {-n num}\n");
        exit(0);
    }

    // allocate memory for the Options structure
    Options *options = malloc(sizeof(Options));
    if (options == NULL) {
        error_exit("Error while allocating memory!", options);
    }

    // setting defaults:
    strcpy(options->interface, "");
    options->specified_interface = 0;
    options->port = -1;
    options->protocols[0] = '\0';
    options->num = 1;

    // go through arguments
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "-i") == 0 || strcmp(argv[i], "--interface") == 0) {
            if (argv[++i] != NULL) {
                int interface_length = 0;
                while (argv[i][++interface_length] != '\0'); // get the length of the interface name
                if (interface_length < MAX_INTERFACE_LENGTH) {
                    strcpy(options->interface, argv[i]);
                    options->specified_interface = 1;
                } else {
                    error_exit("The given interface name is too long!", options);
                }
            }
        } else if (strcmp(argv[i], "-p") == 0 || strcmp(argv[i], "--port") == 0) {
            if (argv[++i] != NULL) {
                // convert the port from string to number
                char *endptr_port;
                int port = strtol(argv[i], &endptr_port, 10);
                // check the port range
                if (port >= 0 && port <= 65535) {
                    options->port = port;
                } else {
                    error_exit("The specified port is out of range!", options);
                }
            } else {
                error_exit("Expected port after -p! Run with --help for more info.", options);
            }
        } else if (strcmp(argv[i], "-n") == 0) {
            if (argv[++i] != NULL) {
                // convert to number
                char *endptr_num;
                options->num = strtol(argv[i], &endptr_num, 10);
            } else {
                error_exit("Expected number after -n! Run with --help for more info.", options);
            }
        // adding the protocols into the Options structure
        } else if (strcmp(argv[i], "-t") == 0 || strcmp(argv[i], "--tcp") == 0) {
            add_protocol(options, TCP);
        } else if (strcmp(argv[i], "-u") == 0 || strcmp(argv[i], "--udp") == 0) {
            add_protocol(options, UDP);
        } else if (strcmp(argv[i], "--icmp4") == 0) {
            add_protocol(options, ICMP4);
        } else if (strcmp(argv[i], "--icmp6") == 0) {
            add_protocol(options, ICMP6);
        } else if (strcmp(argv[i], "--arp") == 0) {
            add_protocol(options, ARP);
        } else if (strcmp(argv[i], "--ndp") == 0) {
            add_protocol(options, NDP);
        } else if (strcmp(argv[i], "--igmp") == 0) {
            add_protocol(options, IGMP);
        } else if (strcmp(argv[i], "--mld") == 0) {
            add_protocol(options, MLD);
        } else {
            error_exit("Unexpected argument! Run with --help for more info.", options);
        }
    }

    return options;
}