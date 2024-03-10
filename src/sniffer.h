// for compatibility reasons
typedef unsigned char u_char;
typedef unsigned short u_short;
typedef unsigned int u_int;

#include <pcap.h>

#include "arguments.h"

#ifndef SNIFFER_H
#define SNIFFER_H

#define TIMESTAMP_SIZE 50 // maximum timestamp length
#define TIMESTAMP_OFFSET 6 // length of the timestamp offset (+01:00)
#define SRC_MAC_OFFSET 6 // offset of the source MAC address

// a struct for ports, stores the source and destination ports
struct ports {
    unsigned short source;
    unsigned short destination;
};

void timestamp_print(const struct pcap_pkthdr *header);

void mac_print(const unsigned char *packet);

void ip_print(const unsigned char *packet);

void port_print(const unsigned char *packet);

void data_print(const unsigned char *packet, int packet_length);

void sniffer(Options *options);

#endif