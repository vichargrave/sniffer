/*
   sniffer.c

   Example packet sniffer using the libpcap packet capture library available
   from http://www.tcpdump.org.
  
   ------------------------------------------

   Copyright (c) 2012 Vic Hargrave

   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at

       http://www.apache.org/licenses/LICENSE-2.0

   Unless required by applicable law or agreed to in writing, software
   distributed under the License is distributed on an "AS IS" BASIS,
   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
   See the License for the specific language governing permissions and
   limitations under the License.
*/

#include <unistd.h>
#include <signal.h>
#include <stdio.h>                      //standard C stuffs
#include <stdlib.h>                     //malloc
#include <errno.h>                      //error code
#include <stdbool.h>                    //boolean type and values
#include <string.h>                     //strlen
#include <sys/socket.h>                 //main sockets header
#include <arpa/inet.h>                  //internet operations definitions
#include </usr/include/netinet/ip.h>    //ipv4 protocols
#include </usr/include/netinet/ip6.h>   //ipv6 protocols
#include </usr/include/pcap/pcap.h>     //pcap library
#include <net/ethernet.h>               //ethernet fundamental onstants
#include <netinet/in.h>                 //internet protocol family
#include <netinet/if_ether.h>           //ethernet header declarations
#include <netinet/ether.h>              //ethernet header declarations
#include <netinet/tcp.h>                //tcp header declarations
#include <netinet/udp.h>                //udp header declarations
#include <netinet/ip_icmp.h>            //icmp header declarations
#include <netinet/icmp6.h> 				//icmpv6 header declarations

pcap_t* pd;

// ----- ----- ----- ----- ----- ----- ----- ----- ----- ----- //

pcap_t* open_pcap_socket(char* device, const char* bpfstr)
{
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* pd;
    uint32_t  srcip, netmask;
    struct bpf_program  bpf;

    // If no network interface (device) is specfied, get the first one.
    if (!*device && !(device = pcap_lookupdev(errbuf)))
    {
        printf("pcap_lookupdev(): %s\n", errbuf);
        return NULL;
    }
    
    // Open the device for live capture, as opposed to reading a packet
    // capture file.
    if ((pd = pcap_open_live(device, BUFSIZ, 1, 0, errbuf)) == NULL)
    {
        printf("pcap_open_live(): %s\n", errbuf);
        return NULL;
    }

    // Get network device source IP address and netmask.
    if (pcap_lookupnet(device, &srcip, &netmask, errbuf) < 0)
    {
        printf("pcap_lookupnet: %s\n", errbuf);
        return NULL;
    }

    // Convert the packet filter epxression into a packet
    // filter binary.
    if (pcap_compile(pd, &bpf, (char*)bpfstr, 0, netmask))
    {
        printf("pcap_compile(): %s\n", pcap_geterr(pd));
        return NULL;
    }

    // Assign the packet filter to the given libpcap socket.
    if (pcap_setfilter(pd, &bpf) < 0)
    {
        printf("pcap_setfilter(): %s\n", pcap_geterr(pd));
        return NULL;
    }

    return pd;
}

// ----- ----- ----- ----- ----- ----- ----- ----- ----- ----- //

void handle_ipv6_next(u_char *packetptr, int header, int size) // Recursive
{
	struct ip6_rthdr* header_rout;
	struct ip6_hbh* header_hop;
	struct ip6_frag* header_frag;
	struct ip6_dest* header_dest;

    switch(header){
		case IPPROTO_ROUTING:
			printf("ROUTING\n");
			header_rout = (struct ip6_rthdr*)(packetptr + size); 
			size += sizeof(struct ip6_rthdr);
			handle_ipv6_next(packetptr, header_rout->ip6r_nxt, size);
			break;
	
		case IPPROTO_HOPOPTS:
			printf("HOP-BY-HOP\n");
			header_hop = (struct ip6_hbh*)(packetptr + size); 
			size += sizeof(struct ip6_hbh);
			handle_ipv6_next(packetptr, header_hop->ip6h_nxt, size);
			break;
	
		case IPPROTO_FRAGMENT:
			printf("FRAGMENTATION\n");
			header_frag = (struct ip6_frag*)(packetptr + size); 
			size += sizeof(struct ip6_frag);
			handle_ipv6_next(packetptr, header_frag->ip6f_nxt, size);
			break;
	
		case IPPROTO_DSTOPTS:
			printf("DESTINATION OPTIONS\n");
			header_dest = (struct ip6_dest*)(packetptr + size); 
			size += sizeof(struct ip6_dest);
			handle_ipv6_next(packetptr, header_dest->ip6d_nxt, size);
			break;

		default:
			printf("UNKNOWN HEADER\n");
	}
}

// ----- ----- ----- ----- ----- ----- ----- ----- ----- ----- //

void handle_ipv6_packet(u_char *packetptr)
{
	struct ip6_hdr* ipv6_header;
	char iphdrInfo[256], srcip[256], dstip[256];

	ipv6_header = (struct ip6_hdr*)packetptr;
	inet_ntop(AF_INET6, &(ipv6_header->ip6_src), srcip, INET6_ADDRSTRLEN);
	inet_ntop(AF_INET6, &(ipv6_header->ip6_dst), dstip, INET6_ADDRSTRLEN);

	sprintf(
		iphdrInfo,
		"\nIPv6 Header:\n"
		"Traffic Class: %i | Flow Label: %i\n"
		"Payload Length: %i | Hop Limit: %i\n"
		"Source IP: %s\n"
		"Destination IP: %s",
		(ntohl(ipv6_header->ip6_vfc) & 0x0ff00000) >> 24,
		ntohl(ipv6_header->ip6_flow) & 0xfffff,
		ntohs(ipv6_header->ip6_plen),
		ipv6_header->ip6_hlim,
		srcip,
		dstip
	);

	printf("%s\n", iphdrInfo);

	handle_ipv6_next(packetptr, ipv6_header->ip6_nxt, sizeof(struct ip6_hdr));

	printf("+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+\n\n");
}

// ----- ----- ----- ----- ----- ----- ----- ----- ----- ----- //

void handle_ipv4_packet(u_char *packetptr)
{
	struct ip* iphdr;
	struct icmphdr* icmphdr;
	struct tcphdr* tcphdr;
	struct udphdr* udphdr;
	unsigned short id, seq;
	char iphdrInfo[256], srcip[256], dstip[256];

	iphdr = (struct ip*)packetptr;
	strcpy(srcip, inet_ntoa(iphdr->ip_src));
	strcpy(dstip, inet_ntoa(iphdr->ip_dst));

	sprintf(
		iphdrInfo,
		"\nIPv4 Header:\n"
		"Ver: %d | Header Length: %d | TOS: 0x%x | Length: %d\n"
		"ID: %d | Fragment Offset: %d\n"
		"TTL: %d | Protocol: %d | Checksum: %d\n"
		"Source IP: %s | Destination IP: %s\n",
		iphdr->ip_v,
		4*iphdr->ip_hl,
		iphdr->ip_tos,
		iphdr->ip_len,
		iphdr->ip_id,
		iphdr->ip_off,
		iphdr->ip_ttl,
		iphdr->ip_p,
		iphdr->ip_sum,
		srcip,
		dstip
	);	
		
	packetptr += 4*iphdr->ip_hl;
	switch (iphdr->ip_p) {
		case IPPROTO_TCP:
			tcphdr = (struct tcphdr*)packetptr;
			printf("TCP %s:%d -> %s:%d\n", srcip, ntohs(tcphdr->source),
				dstip, ntohs(tcphdr->dest));
			printf("%s\n", iphdrInfo);
			printf("%c%c%c%c%c%c Seq: 0x%x Ack: 0x%x Win: 0x%x TcpLen: %d\n",
               (tcphdr->urg ? 'U' : '*'),
               (tcphdr->ack ? 'A' : '*'),
               (tcphdr->psh ? 'P' : '*'),
               (tcphdr->rst ? 'R' : '*'),
               (tcphdr->syn ? 'S' : '*'),
               (tcphdr->fin ? 'F' : '*'),
               ntohl(tcphdr->seq), ntohl(tcphdr->ack_seq),
               ntohs(tcphdr->window), 4*tcphdr->doff);
			break;

		case IPPROTO_UDP:
			udphdr = (struct udphdr*)packetptr;
			printf("UDP %s:%d -> %s:%d\n", srcip, ntohs(udphdr->source),
			dstip, ntohs(udphdr->dest));
			printf("%s\n", iphdrInfo);
			break;

		case IPPROTO_ICMP:
			icmphdr = (struct icmphdr*)packetptr;
			printf("ICMP %s -> %s\n", srcip, dstip);
			printf("%s\n", iphdrInfo);
			memcpy(&id, (u_char*)icmphdr+4, 2);
			memcpy(&seq, (u_char*)icmphdr+6, 2);
			printf("Type:%d Code:%d ID:%d Seq:%d\n", icmphdr->type, icmphdr->code, 
			ntohs(id), ntohs(seq));
			break;
	}

	printf("+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+\n\n");
}

// ----- ----- ----- ----- ----- ----- ----- ----- ----- ----- //

void parse_packet(u_char *user, struct pcap_pkthdr *packethdr, u_char *packetptr)
{
	struct ether_header* ethernet_header;
	int linktype, linkhdrlen, ether_packet = 0;

	// Define ethernet header
	ethernet_header = (struct ether_header*)(packetptr);

	// Determine the datalink layer type.
	if ((linktype = pcap_datalink(pd)) < 0) {
		printf("pcap_datalink(): %s\n", pcap_geterr(pd));
		return;
	}
 
	// Set the datalink layer header size and IP version.

	// Previous to this version, all packets were treated
	// as IPv4 packets. Now, if it's an Ethernet packet,
	// it can differentiate between IPv4 and IPv6.

	switch (linktype) {
		case DLT_NULL:
			linkhdrlen = 4;
			break;

		case DLT_EN10MB:
			linkhdrlen = 14;
			ether_packet = 1;
			break;

		case DLT_SLIP:
			case DLT_PPP:
			linkhdrlen = 24;
			break;

		default:
			printf("Unsupported datalink (%d)\n", linktype);
			return;
    }

	// Advance to the transport layer header then parse and display
	// the fields based on IP version and type of header: tcp, udp or icmp.

	// IPv4
	if (ether_packet) {

		if (ntohs(ethernet_header->ether_type) == ETHERTYPE_IP) {

			handle_ipv4_packet(packetptr + linkhdrlen);
			
		} else if (ntohs(ethernet_header->ether_type) == ETHERTYPE_IPV6) {

			handle_ipv6_packet(packetptr + linkhdrlen);

		} else {

			// ETHERTYPE_ARP or ETHERTYPE_RARP

		}

	} else {

		handle_ipv4_packet(packetptr + linkhdrlen);

	}
}

// ----- ----- ----- ----- ----- ----- ----- ----- ----- ----- //

void bailout(int signo)
{
    struct pcap_stat stats;
 
    if (pcap_stats(pd, &stats) >= 0)
    {
        printf("%d packets received\n", stats.ps_recv);
        printf("%d packets dropped\n\n", stats.ps_drop);
    }
    pcap_close(pd);
    exit(0);
}

// ----- ----- ----- ----- ----- ----- ----- ----- ----- ----- //

int main(int argc, char **argv)
{
    char interface[256] = "", bpfstr[256] = "";
    int packets = 0, c, i;
 
    // Get the command line options, if any
    while ((c = getopt (argc, argv, "hi:n:")) != -1)
    {
        switch (c)
        {
        case 'h':
            printf("usage: %s [-h] [-i ] [-n ] []\n", argv[0]);
            exit(0);
            break;
        case 'i':
            strcpy(interface, optarg);
            break;
        case 'n':
            packets = atoi(optarg);
            break;
        }
    }

    // Get the packet capture filter expression, if any.
    for (i = optind; i < argc; i++)
    {
        strcat(bpfstr, argv[i]);
        strcat(bpfstr, " ");
    }
 
	// Open libpcap, set the program termination signals then start
	// processing packets.
	if ((pd = open_pcap_socket(interface, bpfstr)))
	{
		signal(SIGINT, bailout);
		signal(SIGTERM, bailout);
		signal(SIGQUIT, bailout);

		// Start capturing packets.
		if (pcap_loop(pd, packets, (pcap_handler)parse_packet, 0) < 0)
			printf("pcap_loop failed: %s\n", pcap_geterr(pd));		  

		bailout(0);
	}
	exit(0);
}
