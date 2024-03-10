# IPK Project 2 - ZETA: Network Sniffer

## Compiling
On Linux, the `make` command should compile the program correctly, if you have the `libpcap` library installed. The program requires sudo to run on most interface devices.

## Structure of the code
As I programmed the project in C, the structure is built around that. The `main` function is in the file `main.c`. The `main` function calls the function `arguments_parse` function, which does what the name says, it takes the arguments and parses them into the `Options` structure. It is located in the `arguments.c` file and there are also its helper functions for adding a protocol into the structure and checking if a protocol is already in the structure.

The `main` function then checks if the user specified any interface and if not, the function calls the `interfaces_print` that is located in `interfaces.c` and the function finds all available network devices (using the `libpcap` library) and prints a list of them into the standard output.

If the user specified an interface, the `sniffer` function is called. The `sniffer` function is located in the `sniffer.c` file. The function first looks up the specified device and checks if it exists. Then it opens a pcap live session and calls `filter_parse` function. The function is located in `filter.c`, it parses the arguments and creates a `libpcap` compatible filter string from them.

After the filter string is created, the `sniffer` function calls `pcap_compile` and `pcap_setfilter` to compile the filter and set it to the current session. Then comes the sniffing itself. I decided to create a for loop that calls the `pcap_next` function to get a packet N times (specified by the user, default is once). After the program gets the packet, a bunch of helper functions is called for printing the packet data. These include:
- `timestamp_print` for printing the timestamp
- `mac_print` for printing the source and destination MAC addresses
- frame length is then printed by simple `printf`
- `ip_print` for printing source and destination IP addresses (it also supports IPv6 addresses)
- `port_print` for printing ports (but only with TCP or UDP packets)
- `data_print` that prints the data itself similarly to the way WireShark prints them

The program then closes the pcap session, frees the Options structure from memory and exits with code zero.

## Necessary theory to understand the program
To understand the program functionality, these parts of theory are important:
- the ethernet packet frame structure
- IPv4 and IPv6 headers structures
- TCP and UDP packet structure (for getting ports)
- supported packet types and their usage (TCP, UDP, ICMPv4, ICMPv6, ARP, NDP, IGMP, MLD)
- the ICMPv6 types
- `libpcap` filter format

## Testing
My testing consisted of testing the arguments parsing (which I found as a really important part of the program functionality) and testing the sniffing of the packets itself.

### `arguments.py`
This is a simple script used to test if the program is parsing the arguments correctly. It tests the program automatically and is run by this command `python3 tests/arguments.py` (needs to be run as sudo to unlock the "any" interface, and the ipk-sniffer file needs to be compiled). The results are:
- no arguments, returns 0 - PASSED
- no arguments, lists interfaces - PASSED
- unknown argument, returns 1 - PASSED
- port without TCP or UDP, returns 1 - PASSED
- port with TCP and UDP, returns 0 - PASSED
- port with only TCP, returns 0 - PASSED
- all protocols, returns 0 - PASSED
- none protocols (and no port), returns 0 - PASSED
- --help argument, prints help message - PASSED

### `packets.py`
This script is a little bit more complicated and the testing is not fully automatic like with the `arguments.py`. The file is intended to run on the "top" machine and it sends packets to the referential VM with the sniffer. The file prints how should the sniffer be run and other eventual utilities that should be run on the VM, and then it sends packets.
I run the sniffer alongside WireShark to compare the results and check that they are correct (check the timestamp, IPs, ports, etc.). Output from the script:
```
# IPK SNIFFER PACKET tests
Enter the VM IP address: 192.168.122.11
## TESTING UDP:
run this command in VM: nc -u -l 2222
run sniffer like this: ./ipk-sniffer -i <interface> -p 2222 --udp
press enter to continue...
The UDP packet was sent, you should see the message 'Hello, sniffer!' in the ipk-sniffer output and in WireShark.
type ok/fail: ok
## TESTING TCP:
run this command in VM: nc -l 3333
run sniffer like this: ./ipk-sniffer -i <interface> -p 3333 --tcp
press enter to continue...
The TCP packet was sent, you should see it in the ipk-sniffer output and in WireShark.
type ok/fail: ok
## TESTING ICMPv4:
run sniffer like this: ./ipk-sniffer -i <interface> --icmp4 -n 2
press enter to continue...
The ICMPv4 packet was send, you should see the request and reply packets (with corresponding IPs) in the sniffer.
type ok/fail: ok
## TESTING ICMPv6:
run sniffer like this: ./ipk-sniffer -i <loopback interface> --icmp6 -n 2
run this command in VM: ping -6 -c 1 ::1
press enter to continue...
You should see the two ICMPv6 packets (with same src and dst IPs and MAC addresses) in the sniffer and in WireShark on the loopback device.
type ok/fail: ok
## TESTING ARP:
run sniffer like this: ./ipk-sniffer -i <interface> --arp -n 2
press enter to continue...
The ARP packet was send, you should see the packets (with corresponding IPs) in the sniffer.
type ok/fail: ok
- sending UDP packet: ok
- sending TCP packet: ok
- sending ICMPv4 packet: ok
- sending ICMPv6 packet: ok
- sending ARP packet: ok
```
You can see the outputs from the sniffer in the `tests/packets_out` directory (disclosure: the tcp.out was taken later because I forgot the shell redirect into a file the first time).

## Bibliography
- PROGRAMMING WITH PCAP by Tim Carstens, https://www.tcpdump.org/pcap.html
- PCAP_FINDALLDEVS(3PCAP) MAN PAGE, https://www.tcpdump.org/manpages/pcap_findalldevs.3pcap.html
- PCAP-FILTER(7) MAN PAGE, https://www.tcpdump.org/manpages/pcap-filter.7.html
- RFC 3339 - Date and Time on the Internet: Timestamps
- strftime() function explanation on tutorialspoint, https://www.tutorialspoint.com/c_standard_library/c_function_strftime.htm
- Ethernet frame on Wikipedia, https://en.wikipedia.org/wiki/Ethernet_frame
- Internet Protocol version 4 on Wikipedia, https://en.wikipedia.org/wiki/Internet_Protocol_version_4
- IPv6 packet on Wikipedia, https://en.wikipedia.org/wiki/IPv6_packet
- ICMPv6 on Wikipedia, https://en.wikipedia.org/wiki/ICMPv6
- Jason on StackOverflow, https://stackoverflow.com/a/1493545