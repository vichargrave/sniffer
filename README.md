sniffer
=======

Packet sniffer based on libpcap

Build
=====

To build the test application just cd to the sniffer directory then type "make".

Run
===

Run by specifying an interface and a Berkeley packet filter expression. For 
example this statement will capture all the inbound and outbound TCP packets 
port 80 packets on interface eth0:

./sniffer -i eth0 tcp port 80
