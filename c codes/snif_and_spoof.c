
#include <pcap.h>
#include <stdio.h>
#include <arpa/inet.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <netinet/in.h>
// IPv4 header len without options
#define IP4_HDRLEN 20

// ICMP header len for echo reply (with time stamp)
#define ICMP_HDRLEN 16

//ETHER header len without options
#define SIZE_ETHERNET 14
/* Ethernet header */
struct ethheader {
    u_char  ether_dhost[6]; // destination host temp
    u_char  ether_shost[6]; // source host temp
    u_short ether_type;     // protocol type (IP, ARP, RARP, etc)
};

/* IP Header */
struct ipheader {
    unsigned char      iph_ihl:4,     //IP header length
    iph_ver:4;     //IP version
    unsigned char      iph_tos;       //Type of service
    unsigned short int iph_len;       //IP Packet length (data + header)
    unsigned short int iph_ident;     //Identification
    unsigned short int iph_flag:3,    //Fragmentation flags
    iph_offset:13; //Flags offset
    unsigned char      iph_ttl;       //Time to Live
    unsigned char      iph_protocol;  //Protocol type
    unsigned short int iph_chksum;    //IP datagram checksum
    struct  in_addr    iph_sourceip;  //Source IP temp
    struct  in_addr    iph_destip;    //Destination IP temp
};

/* ICMP Header  */
struct icmpheader {
    unsigned char icmp_type;        // ICMP message type
    unsigned char icmp_code;        // Error code
    unsigned short int icmp_chksum; //Checksum for ICMP Header and data
    unsigned short int icmp_id;     //Used for identifying request
    unsigned short int icmp_seq;    //Sequence number
};
unsigned short calculate_checksum(unsigned short * paddress, int len);
void got_packet(u_char *args, const struct pcap_pkthdr *header,const u_char *packet)
{
    (void)args; // without doing cast to void the compiler make a warring
    (void)header;// without doing cast to void the compiler make a warring
    struct in_addr temp;
    struct ethheader *eth = (struct ethheader *)packet; // the first layer is the ethernet layer
    if (ntohs(eth->ether_type) == 0x0800) { // 0x0800 is IP type
        struct ipheader * ip = (struct ipheader *) (packet + sizeof(struct ethheader));// the second layer is the ip layer
        if(ip->iph_protocol == IPPROTO_ICMP){ // if the next protocol is icmp protocol

            struct icmpheader* icmp = (struct icmpheader*) (packet + sizeof(struct ethheader) + sizeof(struct ipheader));
            char* data= (char*)(packet+SIZE_ETHERNET+IP4_HDRLEN);// this is the data from the echo request
            struct ipheader* send_packet_ip= (struct ipheader *) (packet + sizeof(struct ethheader))
            struct icmpheader* send_packet_icmp = (struct icmpheader*) (packet + sizeof(struct ethheader) + sizeof(struct ipheader));;// this is the icmp header of the reply
            char* send_packet_buf=buf;
            // change between dst request and src reply in the ip header.
            send_packet_ip->iph_destip = ip->iph_sourceip;
            send_packet_ip->iph_sourceip = ip->iph_destip;
            // icmp header

            // Setting ICMP type as to echo reply
            send_packet_icmp->type = 0;

            send_packet_icmp->icmp_chksum = 0;
            send_packet_icmp->icmp_chksum = calculate_checksum((unsigned short *)send_packet_icmp ,icmp_len);
            int icmp_len = ntohs(send_packet_ip->ip_len) - sizeof(struct icmpheader*) - IP4_HDRLEN;

            // Combine the packet
            char send_packet[IP_MAXPACKET];
            // IP header
            memcpy(send_packet, send_packet_ip, IP4_HDRLEN);

            // ICMP header
            memcpy ((send_packet+IP4_HDRLEN), &send_packet_icmp, ICMP_HDRLEN);

            // After ICMP header, add the ICMP data.
            memcpy ((send_packet + ICMP_HDRLEN+IP4_HDRLEN), data, icmp_len);

            // Calculate the ICMP header checksum
            send_packet_icmp.icmp_cksum = calculate_checksum((unsigned short *) (send_packet), ICMP_HDRLEN + icmp_len);
            // after the checksum override the icmp
            memcpy ((send_packet+IP4_HDRLEN), &send_packet_icmp, ICMP_HDRLEN);

            struct sockaddr_in dest_in;
            memset (&dest_in, 0, sizeof (struct sockaddr_in));
            dest_in.sin_family = AF_INET;
            // The port is irrelant for Networking and therefore was zeroed.
            dest_in.sin_addr.s_addr = send_packet_ip->iph_destip;


            // Create raw socket for IP-RAW (make IP-header by yourself)
            int sock = -1;
            if ((sock = socket (AF_INET, SOCK_RAW, IPPROTO_ICMP)) == -1)
            {
                fprintf (stderr, "socket() failed with error: %d",errno);
                fprintf (stderr, "To create a raw socket, the process needs to be run by Admin/root user.\n\n");
                return -1;
            }
            setsockopt(sock, IPPROTO_IP, IP_HDRINCL, &enable, sizeof(enable));
            // Send the packet using sendto() for sending datagrams.
            int sent_package=-1;
            sent_package=sendto (sock, packet, IP4_HDRLEN + ICMP_HDRLEN + datalen, 0, (struct sockaddr *) &dest_in, sizeof (dest_in));
            if (sent_package == -1)
            {
                fprintf (stderr, "sendto() failed with error: %d",errno);
                return -1;
            }
            printf("Sent reply to %s:\n", send_packet_ip->iph_destip);

            // Close the raw socket descriptor
            close(sock);

        }

    }
}

}
int main() {
    pcap_t *handle;
    char errbuf[PCAP_ERRBUF_SIZE];
    struct bpf_program fp;
    char filter_exp[] = "icmp[icmptype] = 8"; // only icmp echo request
    bpf_u_int32 net = 0;

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
unsigned short calculate_checksum(unsigned short *paddress, int len) {
    int nleft = len;
    int sum = 0;
    unsigned short *w = paddress;
    unsigned short answer = 0;

    while (nleft > 1) {
        sum += *w++;
        nleft -= 2;
    }

    if (nleft == 1) {
        *((unsigned char *) &answer) = *((unsigned char *) w);
        sum += answer;
    }

    // add back carry outs from top 16 bits to low 16 bits
    sum = (sum >> 16) + (sum & 0xffff); // add hi 16 to low 16
    sum += (sum >> 16);                 // add carry
    answer = ~sum;                      // truncate to 16 bits

    return answer;
}

