typedef unsigned char u_char;
typedef unsigned short u_short;
typedef unsigned int u_int;

#include <string.h>
#include <pcap.h>

#include "arguments.h"
#include "error.h"
#include "interfaces.h"

//
// Parts of this code were inspired by PCAP_FINDALLDEVS(3PCAP) MAN PAGE
// https://www.tcpdump.org/manpages/pcap_findalldevs.3pcap.html
//

// function for printing all available interfaces
void interfaces_print(Options *options) {
    char error_buffer[PCAP_ERRBUF_SIZE];
    pcap_if_t *device;

    // find all devices
    if (pcap_findalldevs(&device, error_buffer) == -1) {
        char error_string[ERROR_STRING_LENGTH + PCAP_ERRBUF_SIZE] =
            "Error finding devices: ";
        strcat(error_string, error_buffer);
        error_exit(error_string, options);
    }

    // print the device names
    while (device != NULL) {
        printf("%s\n", device->name);
        device = device->next;
    }

    pcap_freealldevs(device);
}