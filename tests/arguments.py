import os

# no arguments => should return 0
os.system("./ipk-sniffer > /dev/null; echo $? > tests/1.out")
with open("tests/1.out", "r") as f:
    if "0" in f.read():
        print("no arguments, returns 0 - PASSED")
    else:
        print("no arguments, returns 0 - FAILED")

# no arguments => should list interfaces (checking for interface any)
os.system("./ipk-sniffer > tests/2.out")
with open("tests/2.out", "r") as f:
    if "any" in f.read():
        print("no arguments, lists interfaces - PASSED")
    else:
        print("no arguments, lists interfaces - FAILED")

# unknown argument => returns 1
os.system("./ipk-sniffer --random_arg 2>/dev/null; echo $? > tests/3.out")
with open("tests/3.out", "r") as f:
    if "1" in f.read():
        print("unknown argument, returns 1 - PASSED")
    else:
        print("unknown argument, returns 1 - FAILED")

# port without tcp or udp => returns 1
os.system("./ipk-sniffer -i any -p 443 2>/dev/null; echo $? > tests/4.out")
with open("tests/4.out", "r") as f:
    if "1" in f.read():
        print("port without TCP or UDP, returns 1 - PASSED")
    else:
        print("port without TCP or UDP, returns 1 - FAILED")

# port with tcp and udp => returns 0
os.system("sudo ./ipk-sniffer -i any -p 443 --tcp --udp -n 0; echo $? > tests/5.out")
with open("tests/5.out", "r") as f:
    if "0" in f.read():
        print("port with TCP and UDP, returns 0 - PASSED")
    else:
        print("port with TCP and UDP, returns 0 - FAILED")

# port with only tcp => returns 0
os.system("sudo ./ipk-sniffer -i any -p 443 --tcp -n 0; echo $? > tests/6.out")
with open("tests/6.out", "r") as f:
    if "0" in f.read():
        print("port with only TCP, returns 0 - PASSED")
    else:
        print("port with only TCP, returns 0 - FAILED")

# all protocols => returns 0
os.system("sudo ./ipk-sniffer -i any -p 443  --tcp --udp --icmp4 --icmp6 --arp --ndp --igmp --mld -n 0; echo $? > tests/7.out")
with open("tests/7.out", "r") as f:
    if "0" in f.read():
        print("all protocols, returns 0 - PASSED")
    else:
        print("all protocols, returns 0 - FAILED")

# none protocols => returns 0
os.system("sudo ./ipk-sniffer -i any -n 0; echo $? > tests/8.out")
with open("tests/8.out", "r") as f:
    if "0" in f.read():
        print("none protocols (and no port), returns 0 - PASSED")
    else:
        print("none protocols (and no port), returns 0 - FAILED")

# --help argument => prints help
os.system("./ipk-sniffer --help > tests/9.out")
with open("tests/9.out", "r") as f:
    if "Usage:" in f.read():
        print("--help argument, prints help message - PASSED")
    else:
        print("--help argument, prints help message - FAILED")
