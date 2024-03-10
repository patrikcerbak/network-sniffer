#ifndef ARGUMENTS_H
#define ARGUMENTS_H

#define MAX_INTERFACE_LENGTH 100 // max length of the interface name
#define MAX_PROTOCOLS 8 // max number of protocol user can specify

enum Protocols {
    TCP = 1,
    UDP,
    ICMP4,
    ICMP6,
    ARP,
    NDP,
    IGMP,
    MLD
};

typedef struct Options {
    char interface[MAX_INTERFACE_LENGTH];
    int specified_interface; // to check if an interface was specified in the arguments
    int port;
    enum Protocols protocols[MAX_PROTOCOLS + 1]; // +1 for '\0'
    int num;
} Options;

int contains_protocol(Options *options, enum Protocols protocol);

void add_protocol(Options *options, enum Protocols protocol);

Options *arguments_parse(int argc, char **argv);

#endif