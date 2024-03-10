import os

print("# IPK SNIFFER PACKET tests")

vm_ip = input("Enter the VM IP address: ")

print("## TESTING UDP:")
print("run this command in VM: nc -u -l 2222")
print("run sniffer like this: ./ipk-sniffer -i <interface> -p 2222 --udp")
input("press enter to continue...")
os.system("echo 'Hello, sniffer!' | nc -u "+ vm_ip +" 2222")
print("The UDP packet was sent, you should see the message 'Hello, sniffer!' in the ipk-sniffer output and in WireShark.")
result1 = input("type ok/fail: ")

print("## TESTING TCP:")
print("run this command in VM: nc -l 3333")
print("run sniffer like this: ./ipk-sniffer -i <interface> -p 3333 --tcp")
input("press enter to continue...")
os.system("echo 'Hello, TCP!' | nc "+ vm_ip +" 3333")
print("The TCP packet was sent, you should see it in the ipk-sniffer output and in WireShark.")
result2 = input("type ok/fail: ")

print("## TESTING ICMPv4:")
print("run sniffer like this: ./ipk-sniffer -i <interface> --icmp4 -n 2")
input("press enter to continue...")
os.system("ping -c 1 " + vm_ip + " > /dev/null")
print("The ICMPv4 packet was send, you should see the request and reply packets (with corresponding IPs) in the sniffer.")
result3 = input("type ok/fail: ")

# only in the VM
print("## TESTING ICMPv6:")
print("run sniffer like this: ./ipk-sniffer -i <loopback interface> --icmp6 -n 2")
print("run this command in VM: ping -6 -c 1 ::1")
input("press enter to continue...")
print("You should see the two ICMPv6 packets (with same src and dst IPs and MAC addresses) in the sniffer and in WireShark on the loopback device.")
result4 = input("type ok/fail: ")

print("## TESTING ARP:")
print("run sniffer like this: ./ipk-sniffer -i <interface> --arp -n 2")
input("press enter to continue...")
os.system("arping -c 1 " + vm_ip + " > /dev/null")
print("The ARP packet was send, you should see the packets (with corresponding IPs) in the sniffer.")
result5 = input("type ok/fail: ")

# the rest of the pocket types are unfortunatelly hard to reproduce with this simple script

print("- sending UDP packet: " + result1)
print("- sending TCP packet: " + result2)
print("- sending ICMPv4 packet: " + result3)
print("- sending ICMPv6 packet: " + result4)
print("- sending ARP packet: " + result5)