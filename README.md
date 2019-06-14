# sniffer

Example code from my Develop a Packet Sniffer with libpcap blog.

## Build

1. Install the pcap library by typing 'sudo apt-get install libpcap-dev'.
2. cd to the 'sniffer' directory.
3. Type 'make'.
4. If the previous method doesn't work, type 'gcc -o sniffer sniffer.c -lpcap -Wall -D_GNU_SOURCE -I.'.

## Run

Run by specifying an interface and a Berkeley packet filter expression. For 
example this statement will capture all the inbound and outbound TCP packets 
port 80 packets on interface eth0:

```
./sniffer -i eth0 tcp port 80
```
