#include <stdio.h>
#include <pcap.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <stdint.h> 
#include <inttypes.h>

/* Ethernet addresses are 6 bytes */
#define ETHER_ADDR_LEN	6

/* ethernet headers are always exactly 14 bytes */
#define SIZE_ETHERNET 14

#define IPv4_ETHERTYPE 0x800
#define UDP 17
#define SIZE_UDP 8
#define DHCP_SERVER_PORT   67
#define DHCP_CLIENT_PORT   68
#define MAX_DHCP_CHADDR_LENGTH           16
#define MAX_DHCP_SNAME_LENGTH            64
#define MAX_DHCP_FILE_LENGTH             128
#define MAX_DHCP_OPTIONS_LENGTH          312

#define IP_HL(ip)		(((ip)->ip_vhl) & 0x0f)
#define IP_V(ip)		(((ip)->ip_vhl) >> 4)

/* Ethernet header */
struct sniff_ethernet {
	u_char          ether_dhost[ETHER_ADDR_LEN];	/* Destination host address */
	u_char          ether_shost[ETHER_ADDR_LEN];	/* Source host address */
	u_short         ether_type;	/* IP? ARP? RARP? etc */
};

	/* IP header */
struct sniff_ip {
	u_char          ip_vhl;	/* version << 4 | header length >> 2 */
	u_char          ip_tos;	/* type of service */
	u_short         ip_len;	/* total length */
	u_short         ip_id;	/* identification */
	u_short         ip_off;	/* fragment offset field */
#define IP_RF 0x8000		/* reserved fragment flag */
#define IP_DF 0x4000		/* dont fragment flag */
#define IP_MF 0x2000		/* more fragments flag */
#define IP_OFFMASK 0x1fff	/* mask for fragmenting bits */
	u_char          ip_ttl;	/* time to live */
	u_char          ip_p;	/* protocol */
	u_short         ip_sum;	/* checksum */
	struct in_addr  ip_src, ip_dst;    /* source and dest address */
	//u_char ip_src;
	//u_char ip_dst;	
};
/* UDP header */
struct sniff_udp {
	uint16_t        sport;	/* source port */
	uint16_t        dport;	/* destination port */
	uint16_t        udp_length;
	uint16_t        udp_sum;	/* checksum */
};

struct dhcp_packet{
        u_int8_t  op;                   /* packet type */
        u_int8_t  htype;                /* type of hardware address for this machine (Ethernet, etc) */
        u_int8_t  hlen;                 /* length of hardware address (of this machine) */
        u_int8_t  hops;                 /* hops */
        u_int32_t xid;                  /* random transaction id number - chosen by this machine */
        u_int16_t secs;                 /* seconds used in timing */
        u_int16_t flags;                /* flags */
        struct in_addr ciaddr;          /* IP address of this machine (if we already have one) */
        struct in_addr yiaddr;          /* IP address of this machine (offered by the DHCP server) */
        struct in_addr siaddr;          /* IP address of DHCP server */
        struct in_addr giaddr;          /* IP address of DHCP relay */
        unsigned char chaddr [MAX_DHCP_CHADDR_LENGTH];      /* hardware address of this machine */
        char sname [MAX_DHCP_SNAME_LENGTH];    /* name of DHCP server */
        char file [MAX_DHCP_FILE_LENGTH];      /* boot file name (used for diskless booting?) */
	char options[MAX_DHCP_OPTIONS_LENGTH];  /* options */
        };

int
main(int argc, char *argv[])
{
	char           *filename, errbuf[PCAP_ERRBUF_SIZE];
	pcap_t         *handle;
	const u_char   *packet;	/* The actual packet */
	struct pcap_pkthdr header;	/* The header that pcap gives us */
	const struct sniff_ethernet *ethernet;	/* The ethernet header */
	const struct sniff_ip *ip;	/* The IP header */
	const struct sniff_udp *udp;	/* The UDP header */
	const struct dhcp_packet *dhcp;
	u_int           size_ip;
	u_short         source_port, dest_port;
	char           *source, *destination;
 
	if (argc < 2) {
		fprintf(stderr, "Usage: readfile filename\n");
		return (2);
	}
	filename = argv[1];
	handle = pcap_open_offline(filename, errbuf);
	if (handle == NULL) {
		fprintf(stderr, "Couldn't open file %s: %s\n", filename, errbuf);
		return (2);
	}
	printf("%s\n","----------------------------------------------------------------------------------------------------------------------------------------------" );
	while (1) {
/* Grab a packet */
		packet = pcap_next(handle, &header);
		if (packet == NULL) {	/* End of file */
			break;
		}
		ethernet = (struct sniff_ethernet *) (packet);
		ip = (struct sniff_ip *) (packet + SIZE_ETHERNET);
		udp =(struct sniff_udp *) (packet + SIZE_ETHERNET+ IP_HL(ip)*4);

		source_port = ntohs(udp->sport);
		dest_port = ntohs(udp->dport);
						
		if ((source_port == DHCP_SERVER_PORT || dest_port == DHCP_SERVER_PORT) || 
			(source_port == DHCP_CLIENT_PORT || dest_port == DHCP_CLIENT_PORT)) {				
				
				dhcp =(struct dhcp_packet *) (packet + SIZE_ETHERNET+ IP_HL(ip)*4 + SIZE_UDP);
				if (dhcp->op == 1)
					printf("message type : %s (%u) | ","Request",dhcp->op );
				else
					printf("message type : %s (%u) | ","Reply",dhcp->op );

				printf("hardware adress type : %u | hardware lenght : %u | hops : %u | already Ip : %s | Ip offered by dhcp : %s | DHCP server IP : %s | DHCP relay IP : %s |hardware addr : ",
					dhcp->htype,dhcp->hlen,dhcp->hops,inet_ntoa(dhcp->ciaddr) , inet_ntoa(dhcp->yiaddr), inet_ntoa(dhcp->siaddr), inet_ntoa(dhcp->giaddr));
				
				for (int i = 0; i < 6; ++i)
				{
					printf("%x.",dhcp->chaddr[i] );
				}
				printf("\n\n");
							
			}
					
	}
printf("%s\n","----------------------------------------------------------------------------------------------------------------------------------------------" );

	pcap_close(handle);

	return (0);
}
