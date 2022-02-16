#include <stdio.h>
#include <pcap.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <string.h>
#include <net/ethernet.h>
#include <netinet/tcp.h>
/* Ethernet header */
struct ethheader {
    u_char  ether_dhost[ETHER_ADDR_LEN]; /* destination host address */
    u_char  ether_shost[ETHER_ADDR_LEN]; /* source host address */
    u_short ether_type;                  /* IP? ARP? RARP? etc */
};
/* IP Header */
struct ipheader {
    unsigned char      iph_ihl:4, //IP header length
    iph_ver:4;//IP version
    unsigned char      iph_tos; //Type of service
    unsigned short int iph_len; //IP Packet length (data + header)
    unsigned short int iph_ident; //Identification
    unsigned short int iph_flag:3, //Fragmentation flags
    iph_offset:13; //Flags offset
    unsigned char      iph_ttl; //Time to Live
    unsigned char      iph_protocol; //Protocol type
    unsigned short int iph_chksum; //IP datagram checksum
    struct  in_addr    iph_sourceip; //Source IP address
    struct  in_addr    iph_destip;   //Destination IP address
};
/* ICMP Header  */
struct icmpheader {
    unsigned char icmp_type; // ICMP message type
    unsigned char icmp_code; // Error code
    unsigned short int icmp_chksum; //Checksum for ICMP Header and data
    unsigned short int icmp_id;     //Used for identifying request
    unsigned short int icmp_seq;    //Sequence number
};

void got_packet(u_char *args, const struct pcap_pkthdr *header,const u_char *packet)
{
    (void)args; // without doing cast to void the compiler make a warring
    (void)header;// without doing cast to void the compiler make a warring
    struct ethheader *eth = (struct ethheader *)packet; // the first layer is the ethernet layer
    if (ntohs(eth->ether_type) == 0x0800) { // 0x0800 is IP type
        struct ipheader * ip = (struct ipheader *) (packet + sizeof(struct ethheader));// the second layer is the ip layer

            printf("IP SRC: %s\n", inet_ntoa(ip->iph_sourceip));
            printf("IP DEST: %s\n", inet_ntoa(ip->iph_destip));
        if (ip->iph_protocol == IPPROTO_TCP)
            printf("   Protocol: TCP\n");

    }

    }
}
int main()
{
    pcap_t *handle;
    char errbuf[PCAP_ERRBUF_SIZE];
    struct bpf_program fp;
    char filter_exp[] = "proto tcp and portrange 10-100;
    bpf_u_int32 net=0;

    // Step 1: Open live pcap session on NIC with name eth3
    handle = pcap_open_live("enp0s3", BUFSIZ, 1, 1000, errbuf);
    if (handle == NULL) {
        perror("opening error");
    }
    // Step 2: Compile filter_exp into BPF psuedo-code
    pcap_compile(handle, &fp, filter_exp, 0, net);
    pcap_setfilter(handle, &fp);

    // Step 3: Capture packets
    pcap_loop(handle, -1, got_packet, NULL);

    pcap_close(handle);   //Close the handle
    return 0;
}



