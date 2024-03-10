// for compatibility reasons
typedef unsigned char u_char;
typedef unsigned short u_short;
typedef unsigned int u_int;

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <time.h>
#include <arpa/inet.h>
#include <net/ethernet.h>
#include <netinet/ether.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <netinet/if_ether.h>
#include <pcap.h>

// this will not work on Windows since, the <arpa/inet.h>, <netinet/ether.h> and <netinet/if_ether.h>
// are UNIX specific headers 

#include "error.h"
#include "arguments.h"
#include "filter.h"
#include "sniffer.h"


// function for printing the timestamp pcap header
void timestamp_print(const struct pcap_pkthdr *header) {
    char timestamp[TIMESTAMP_SIZE];
    char offset[TIMESTAMP_OFFSET];

    // get and print timestamp
    struct tm *time = localtime(&header->ts.tv_sec);
    strftime(timestamp, sizeof(timestamp), "%Y-%m-%dT%H:%M:%S.", time);
    printf("timestamp: %s", timestamp);

    // print the miliseconds
    printf("%03ld", header->ts.tv_usec / 1000);
    strftime(offset, sizeof(offset), "%z", time);

    // print the offset with ":"
    printf("%c%c%c:%c%c\n", offset[0], offset[1], offset[2], offset[3], offset[4]);
}

// function for printing the source and destination MAC addresses
void mac_print(const unsigned char *packet) {
    const unsigned char *dst_mac = packet;
    const unsigned char *src_mac = packet + SRC_MAC_OFFSET;
    
    // prints the MAC addresses char by char
    printf("src MAC: %02x:%02x:%02x:%02x:%02x:%02x\n", src_mac[0], src_mac[1], src_mac[2], src_mac[3], src_mac[4], src_mac[5]);
    printf("dst MAC: %02x:%02x:%02x:%02x:%02x:%02x\n", dst_mac[0], dst_mac[1], dst_mac[2], dst_mac[3], dst_mac[4], dst_mac[5]);
}

// print the source and destination IP addresses
void ip_print(const unsigned char *packet) {
    char source_ip[INET6_ADDRSTRLEN];
    char dest_ip[INET6_ADDRSTRLEN];

    struct ethhdr *eth_header = (struct ethhdr*)packet; // ethhdr to check if the IP is  IPv6 or IPv4
    
    if (ntohs(eth_header->h_proto) == ETH_P_IPV6) {
        // get the IPv6 addresses
        struct ip6_hdr *ip_header = (struct ip6_hdr*)(packet + sizeof(struct ethhdr));
        inet_ntop(AF_INET6, &(ip_header->ip6_src), source_ip, INET6_ADDRSTRLEN);
        inet_ntop(AF_INET6, &(ip_header->ip6_dst), dest_ip, INET6_ADDRSTRLEN);
    } else {
        // otherwise, get the IPv4 addresses
        struct iphdr *ip_header = (struct iphdr*)(packet + sizeof(struct ethhdr));
        inet_ntop(AF_INET, &(ip_header->saddr), source_ip, INET_ADDRSTRLEN);
        inet_ntop(AF_INET, &(ip_header->daddr), dest_ip, INET_ADDRSTRLEN);
    }

    printf("src IP: %s\n", source_ip);
    printf("dst IP: %s\n", dest_ip);
}

// function for printing the ports
void port_print(const unsigned char *packet) {
    struct ethhdr *eth_header = (struct ethhdr*)packet;

    // check if the packet is IPv6
    if (ntohs(eth_header->h_proto) == ETH_P_IPV6) {
        struct ip6_hdr *ip_header = (struct ip6_hdr*)(packet + sizeof(struct ethhdr));
        // check if the packet is TCP or UDP
        if (ip_header->ip6_ctlun.ip6_un1.ip6_un1_nxt == IPPROTO_TCP || ip_header->ip6_ctlun.ip6_un1.ip6_un1_nxt == IPPROTO_UDP) {
            // get the ports into the ports structure
            struct ports *ports = (struct ports*)(packet + sizeof(struct ethhdr) + sizeof(struct ip6_hdr));
            printf("src port: %d\n", ntohs(ports->source));
            printf("dst port: %d\n", ntohs(ports->destination));
        }
    } else {
        struct iphdr *ip_header = (struct iphdr*)(packet + sizeof(struct ethhdr));
        if (ip_header->protocol == IPPROTO_TCP || ip_header->protocol == IPPROTO_UDP) {
            // check (with the ip_header) if the protocol is TCP or UDP, otherwise don't print anything
            struct ports *ports = (struct ports*)(packet + sizeof(struct ethhdr) + sizeof(struct iphdr));
            printf("src port: %d\n", ntohs(ports->source));
            printf("dst port: %d\n", ntohs(ports->destination));
        }
    }
}

// function for printing the packet itself
void data_print(const unsigned char *packet, int packet_length) {
    unsigned char bytes_array[16]; // bytes on one "row"
    int j = 0; // counter of the printed bytes on row

    for (int i = 0; i < packet_length; i++) {
        if (i % 16 == 0) {
            // if it is at the start of a row, print the 0xNNNN offset
            printf("0x%04x:", i);
        }

        printf(" %02x", packet[i]); // print a byte of data

        bytes_array[j++] = packet[i]; // add the byte into the bytes array

        // if the program is at the ond of a row or at the end of the packet...
        if (j == 16 || i + 1 == packet_length) {
            if (j == 16) {
                // if the row is full (has 16 bytes), print one space
                printf(" ");
            } else {
                // if the row is not full, calculate the number of spaces to print before the data
                // 3 = length of one printed char, (16 - j) = the number of data "missing" from the row, + 1 = space at the end of row
                int spaces_to_print = 3 * (16 - j) + 1;
                for (int k = 0; k < spaces_to_print; k++) {
                    // print the spaces needed
                    printf(" ");
                }
            }
            
            // print the data as chars
            for (int k = 0; k < j; k++) {
                if (k == 8) {
                    // space every 8 chars
                    printf(" ");
                }
                if (bytes_array[k] >= 31 && bytes_array[k] <= 126) {
                    // print only printable characters
                    printf("%c", bytes_array[k]);
                } else {
                    // otherwise print dot
                    printf (".");
                }
            }
            printf("\n");
            j = 0;
        }
    }
}

//
// Parts (mainly the structure of the pcap library functions) of this sniffer() function
// were inspired by PROGRAMMING WITH PCAP by Tim Carstens.
// https://www.tcpdump.org/pcap.html
// The license for those parts is at the bottom of this file.
//

// function for sniffin the packets
void sniffer(Options *options) {
    char error_buffer[PCAP_ERRBUF_SIZE]; // error buffer
    bpf_u_int32 net; // net
    bpf_u_int32 mask; // netmask
    pcap_t *handle; // session handle
    struct bpf_program filter; // filter
    struct pcap_pkthdr header; // header from pcap
    const unsigned char *packet; // the packet itself

    // lookup the device specified
    if (pcap_lookupnet(options->interface, &net, &mask, error_buffer) == -1) {
        char error_string[ERROR_STRING_LENGTH + PCAP_ERRBUF_SIZE] =
            "Cannot get netmask for the given device: ";
        strcat(error_string, error_buffer);
        error_exit(error_string, options);
    }

    // open the session
    handle = pcap_open_live(options->interface, BUFSIZ, 1, 1000, error_buffer);
    if (handle == NULL) {
        char error_string[ERROR_STRING_LENGTH + PCAP_ERRBUF_SIZE] =
            "Cannot open device: ";
        strcat(error_string, error_buffer);
        error_exit(error_string, options);
    }

    // parse and compile the filter
    char *filter_string = filter_parse(options);
    if (pcap_compile(handle, &filter, filter_string, 0, net) == -1) {
        free(filter_string);
        error_exit("Cannot parse the filter!", options);
    }
    free(filter_string);

    // set the filter
    if (pcap_setfilter(handle, &filter) == -1) {
        error_exit("Cannot set the filter!", options);
    }

    // sniff the packets num times
    for (int i = 0; i < options->num; i++) {
        packet = pcap_next(handle, &header); // get packet

        // print the packet info
        timestamp_print(&header);
        mac_print(packet);
        printf("frame length: %d bytes\n", header.caplen);
        ip_print(packet);
        port_print(packet);
        printf("\n");
        data_print(packet, header.caplen); // print the packet data

        if (i != options->num - 1) {
            // only print new line between packets, not after the last one
            printf("\n");
        }
    }

    pcap_close(handle);
}


/* license for PARTS of this code:

Copyright (c) Tim Carstens. All rights reserved.

Redistribution and use in source and binary forms are permitted provided that the above copyright
notice and this paragraph are duplicated in all such forms and that any documentation, advertising
materials, and other materials related to such distribution and use acknowledge that the software
was developed by the <copyright holder>. The name of the <copyright holder> may not be used to
endorse or promote products derived from this software without specific prior written permission.
THIS SOFTWARE IS PROVIDED `'AS IS″ AND WITHOUT ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, WITHOUT
LIMITATION, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE.
*/