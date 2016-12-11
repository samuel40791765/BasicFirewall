/* Demonstration program of reading packet trace files recorded by pcap
 * (used by tshark and tcpdump) and dumping out some corresponding information
 * in a human-readable form.
 *
 * Note, this program is limited to processing trace files that contains
 * UDP packets.  It prints the timestamp, source port, destination port,
 * and length of each such packet.
 */
#include <iostream>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fstream>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <net/if.h>
#include <netinet/if_ether.h>
#include <arpa/inet.h>
#include <pcap.h>
#include <vector>


/* We've included the UDP header struct for your ease of customization.
 * For your protocol, you might want to look at netinet/tcp.h for hints
 * on how to deal with single bits or fields that are smaller than a byte
 * in length.
 *
 * Per RFC 768, September, 1981.
 */

 using namespace std;
struct UDP_hdr {
	u_short	uh_sport;		/* source port */
	u_short	uh_dport;		/* destination port */
	u_short	uh_ulen;		/* datagram length */
	u_short	uh_sum;			/* datagram checksum */
};


/* Some helper functions, which we define at the end of this file. */

/* Returns a string representation of a timestamp. */
const char *timestamp_string(struct timeval ts);

/* Report a problem with dumping the packet with the given timestamp. */
void problem_pkt(struct timeval ts, const char *reason);

/* Report the specific problem of a packet being too short. */
void too_short(struct timeval ts, const char *truncated_hdr);

/* prototype of the packet handler */
void packet_handler(u_char *param, const struct pcap_pkthdr *header, const u_char *pkt_data);


bool packetinfo(const unsigned char *packet, struct timeval ts, unsigned int capture_len, vector<string> rulesrc, vector<string> ruledest,vector<int> rulesrcprt,vector<int> ruledestprt)
{
	struct ip *ip;
	struct UDP_hdr *udp;
	struct tcphdr *tcp;
	unsigned int IP_header_length;

	/* For simplicity, we assume Ethernet encapsulation. */

	if (capture_len < sizeof(struct ether_header))
		{
		/* We didn't even capture a full Ethernet header, so we
		 * can't analyze this any further.
		 */
		too_short(ts, "Ethernet header");
		return false;
		}

	/* Skip over the Ethernet header. */
	packet += sizeof(struct ether_header);
	capture_len -= sizeof(struct ether_header);

	if (capture_len < sizeof(struct ip))
		{ /* Didn't capture a full IP header */
		too_short(ts, "IP header");
		return false;
		}

	ip = (struct ip*) packet;
	IP_header_length = ip->ip_hl * 4;	/* ip_hl is in 4-byte words */

	fprintf(stderr, "SRC: %s\n", inet_ntoa(ip->ip_src));
	fprintf(stderr, "DES: %s\n", inet_ntoa(ip->ip_dst));
	if (capture_len < IP_header_length)
		{ /* didn't capture the full IP header including options */
		too_short(ts, "IP header with options");
		return false;
		}

	if (ip->ip_p == IPPROTO_UDP){
		packet += IP_header_length;
		capture_len -= IP_header_length;

		if (capture_len < sizeof(struct UDP_hdr)) {
			too_short(ts, "UDP header");
			return false;
		}
		
		udp = (struct UDP_hdr*) packet;
	
		printf("%s UDP src_port=%d dst_port=%d length=%d\n",
			timestamp_string(ts),
			ntohs(udp->uh_sport),
			ntohs(udp->uh_dport),
			ntohs(udp->uh_ulen));
		for(int i=0;i<rulesrc.size();i++){
			if(rulesrc[i].compare(inet_ntoa(ip->ip_src))==0 && ruledest[i].compare(inet_ntoa(ip->ip_dst))==0){
				if(rulesrcprt[i]==ntohs(udp->uh_sport) && ruledestprt[i]==ntohs(udp->uh_dport))
					
					return true;
			}
		}
	}
	else if(ip->ip_p == IPPROTO_TCP){
		packet += IP_header_length;
		capture_len -= IP_header_length;

		if (capture_len < sizeof(struct tcphdr)) {
			too_short(ts, "TCP header");
			return false;
		}
		
		tcp = (struct tcphdr*) packet;
	
		printf("%s TCP src_port=%d dst_port=%d\n",
			timestamp_string(ts),
			ntohs(tcp->th_sport),
			ntohs(tcp->th_dport));
		for(int i=0;i<rulesrc.size();i++){
			if(rulesrc[i].compare(inet_ntoa(ip->ip_src))==0 && ruledest[i].compare(inet_ntoa(ip->ip_dst))==0){
				if(rulesrcprt[i]==ntohs(tcp->th_sport) && ruledestprt[i]==ntohs(tcp->th_dport))
					
					return true;
			}
		}
	}

	return false;
	
	/* Skip over the IP header to get to the UDP header. */
	}


int main(int argc, char *argv[])
	{
	
	vector<string> rulesrc, ruledest;
	vector<int> rulesrcprt,ruledestprt;
	
	pcap_t *pcap;
	const unsigned char *packet;
	char errbuf[PCAP_ERRBUF_SIZE];
	struct pcap_pkthdr header;
	int pkt_count = 0;

	pcap_t *adhandle;
	pcap_dumper_t *dumpfile;

	/* Skip over the program name. */
	++argv; --argc;
	std::ifstream infile(argv[0]);
    string rulesrctemp,ruledesttemp;
    int rulesrcprttemp,ruledestprttemp;
    while(infile>>rulesrctemp>>ruledesttemp>>rulesrcprttemp>>ruledestprttemp){
    	rulesrc.push_back(rulesrctemp);
    	ruledest.push_back(ruledesttemp);
    	rulesrcprt.push_back(rulesrcprttemp);
    	ruledestprt.push_back(ruledestprttemp);
    }
	
    for(int i=0;i<rulesrc.size();i++)
		cout<<rulesrc[i]<<" "<<ruledest[i]<<" "<<rulesrcprt[i]<<" "<<ruledestprt[i]<<endl;
	/* We expect exactly one argument, the name of the file to dump. */
	if ( argc != 3 )
		{
		fprintf(stderr, "program requires three arguments, the trace file to dump\n");
		exit(1);
		}

	pcap = pcap_open_offline(argv[1], errbuf);
	if (pcap == NULL)
		{
		fprintf(stderr, "error reading pcap file: %s\n", errbuf);
		exit(1);
		}

	dumpfile = pcap_dump_open(pcap, argv[2]);

    	if(dumpfile==NULL)
    	{
        	fprintf(stderr,"\nError opening output file\n");
        	return -1;
    	}

	/* Now just loop through extracting packets as long as we have
	 * some to read.
	 */
	while ((packet = pcap_next(pcap, &header)) != NULL){
		printf("get a packet i%d\n", pkt_count);
		pkt_count++;
		if(!packetinfo(packet, header.ts, header.caplen, rulesrc, ruledest, rulesrcprt, ruledestprt))
			pcap_dump((unsigned char *) dumpfile, &header, packet);
		else
			cout<<"Blocked packet"<<endl;
		
		
	}

	// terminate
	return 0;
	}


/* Note, this routine returns a pointer into a static buffer, and
 * so each call overwrites the value returned by the previous call.
 */
const char *timestamp_string(struct timeval ts)
	{
	static char timestamp_string_buf[256];

	sprintf(timestamp_string_buf, "%d.%06d",
		(int) ts.tv_sec, (int) ts.tv_usec);

	return timestamp_string_buf;
	}

void problem_pkt(struct timeval ts, const char *reason)
	{
	fprintf(stderr, "%s: %s\n", timestamp_string(ts), reason);
	}

void too_short(struct timeval ts, const char *truncated_hdr)
	{
	fprintf(stderr, "packet with timestamp %s is truncated and lacks a full %s\n",
		timestamp_string(ts), truncated_hdr);
	}

/* Callback function invoked by libpcap for every incoming packet */
void packet_handler(u_char *dumpfile, const struct pcap_pkthdr *header, const u_char *pkt_data)
{
    /* save the packet on the dump file */
    pcap_dump(dumpfile, header, pkt_data);
}
