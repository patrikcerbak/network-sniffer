#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include "error.h"
#include "arguments.h"
#include "filter.h"

//
// The information about the pcap filters was taken from PCAP-FILTER(7) MAN PAGE
// https://www.tcpdump.org/manpages/pcap-filter.7.html
//

// function for parsing the options protocols and port and it generates a pcap filter string
char *filter_parse(Options *options) {
    char *filter_string = calloc(FILTER_STRING_LENGTH, sizeof(char));
    int already_wrote = 0; // to tell if it already wrote something or not

    // write the port if user specified it
    if (options->port != -1) {
        char port_str[MAX_SUBSTRING_LENGTH] = "";
        if (contains_protocol(options, TCP) && contains_protocol(options, UDP)) {
            // if user specified both TCP and UDP
            sprintf(port_str, "((port %d) and (tcp or udp))", options->port);
        } else if (contains_protocol(options, TCP)) {
            // user specified TCP only
            sprintf(port_str, "((port %d) and (tcp))", options->port);
        } else if (contains_protocol(options, UDP)) {
            // user specified UDP only
            sprintf(port_str, "((port %d) and (udp))", options->port);
        } else {
            error_exit("Expected TCP or UDP arguments wihen using port!", options);
        }
        strcat(filter_string, port_str);
        already_wrote = 1;
    }

    // if user hasn't specified port
    if (!already_wrote) {
        // but has specified TCP
        if (options->protocols[0] == '\0' || contains_protocol(options, TCP)) {
            strcat(filter_string, "(tcp)");
            already_wrote = 1;
        }
        // or UDP
        if (options->protocols[0] == '\0' || contains_protocol(options, UDP)) {
            if (already_wrote) {
                // if there is already something written to the filter_string, add "or" between the filters
                strcat(filter_string, " or ");
            }
            strcat(filter_string, "(udp)");
            already_wrote = 1;
        }
    }

    // --icmp4
    if (options->protocols[0] == '\0' || contains_protocol(options, ICMP4)) {
        if (already_wrote) {
            strcat(filter_string, " or ");
        }
        strcat(filter_string, "(icmp)");
        already_wrote = 1;
    }

    // --icmp6
    if (options->protocols[0] == '\0' || contains_protocol(options, ICMP6)) {
        if (already_wrote) {
            strcat(filter_string, " or ");
        }
        // only take echo request/response packets
        strcat(filter_string, "((icmp6) and (icmp6[0] == 128 or icmp6[0] == 129))");
        already_wrote = 1;
    }

    // --arp
    if (options->protocols[0] == '\0' || contains_protocol(options, ARP)) {
        if (already_wrote) {
            strcat(filter_string, " or ");
        }
        strcat(filter_string, "(arp)");
        already_wrote = 1;
    }

    // --ndp
    if (options->protocols[0] == '\0' || contains_protocol(options, NDP)) {
        if (already_wrote) {
            strcat(filter_string, " or ");
        }
        strcat(filter_string, "((icmp6) and (icmp6[0] == 133 or icmp6[0] == 134 or icmp6[0] == 135 or icmp6[0] == 136 or icmp6[0] == 137))");
        already_wrote = 1;
    }

    // --igmp
    if (options->protocols[0] == '\0' || contains_protocol(options, IGMP)) {
        if (already_wrote) {
            strcat(filter_string, " or ");
        }
        strcat(filter_string, "(igmp)");
        already_wrote = 1;
    }

    // --mld
    if (options->protocols[0] == '\0' || contains_protocol(options, MLD)) {
        if (already_wrote) {
            strcat(filter_string, " or ");
        }
        strcat(filter_string, "((icmp6) and (icmp6[0] == 130 or icmp6[0] == 131 or icmp6[0] == 132))");
        already_wrote = 1;
    }

    return filter_string;
}
