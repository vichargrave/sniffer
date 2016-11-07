# sniffer

Example code from my Develop a Packet Sniffer with libpcap blog.

## Build

1. cd to the 'sniffer' directory.
2. Type 'make'.

## Run

Run by specifying an interface and a Berkeley packet filter expression. For 
example this statement will capture all the inbound and outbound TCP packets 
port 80 packets on interface eth0:

```
./sniffer -i eth0 tcp port 80
```
