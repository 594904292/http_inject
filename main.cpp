#include <sys/time.h>
#include <netinet/in.h>
#include <net/ethernet.h>
#include <pcap/pcap.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/ip_icmp.h>
#include <arpa/inet.h>
#include <netinet/ether.h>
#include <libnet.h>

#define PROMISCOUS 1
#define NONPROMISCUOUS 0

// IP 헤더 구조체
struct ip *iph;
// TCP 헤더 구조체
struct tcphdr *tcph;

int menu=0;

void print_data(const u_char *packet, int len) {
    unsigned int i, j;

    for(i=0; i<len+((len % 16) ? (16 - len % 16) : 0); i++) {
        if(i % 16 == 0) printf("       0x%04x: ", i);
        if(i < len) printf("%02x ", 0xFF & ((char*)packet)[i]);
        else printf("   ");

        if(i % 16 == (16 - 1)) {
            for(j=i-(16 - 1); j <= i; j++) {
                if(j>=len) putchar(' ');
                else if(isprint(((char*)packet)[j])) putchar(0xFF & ((char*)packet)[j]);
                else putchar('.');
            }
            putchar('\n');
        }
    }
}

// http://kaspyx.kr/36 // ip checksum calc
// http://www.onurmark.co.kr/?p=217
void compute_tcp_checksum(struct iphdr *ip_header, unsigned short *tcp_header_and_data) {
    register unsigned long sum = 0;
    unsigned short tcp_len = ntohs(ip_header->tot_len) - (ip_header->ihl << 2);
    struct tcphdr *tcp_header = (struct tcphdr *)(tcp_header_and_data);

    // ip_header(pseudo header) checksum calc (level 1)
    sum += (ip_header->saddr >> 16) & 0xFFFF;
    sum += (ip_header->saddr) & 0xFFFF;
    sum += (ip_header->daddr >> 16) & 0xFFFF;
    sum += (ip_header->daddr) & 0xFFFF;
    sum += htons(IPPROTO_TCP);
    sum += htons(tcp_len);

    // tcp data and header checksum calc (level2)
    tcp_header->check = 0;
    while (tcp_len > 1) {
        sum += * tcp_header_and_data++;
        tcp_len -= 2;
    }


    if(tcp_len > 0)
        sum += ((*tcp_header_and_data)&htons(0xFF00));
    while (sum>>16)
        sum = (sum & 0xffff) + (sum >> 16);

    tcp_header->check = (unsigned short)~sum;
}

u_short ip_checksum( u_short len_ip_header, u_short * buff ) {
        u_short word16;
        u_int sum = 0;
        u_short i;
        // make 16 bit words out of every two adjacent 8 bit words in the packet
        // and add them up
        for( i = 0; i < len_ip_header; i = i+2 ) {
                word16 = ( ( buff[i]<<8) & 0xFF00 )+( buff[i+1] & 0xFF );
                sum = sum + (u_int) word16;
        }
        // take only 16 bits out of the 32 bit sum and add up the carries
        while( sum >> 16 )
            sum = ( sum & 0xFFFF ) + ( sum >> 16 );
        // one's complement the result
        sum = ~sum;

        return ((u_short) sum);
}

void packetfilter_callback(u_char *pcd, const struct pcap_pkthdr *pkthdr, const u_char *packet) {
    static int count = 1;
    struct libnet_ethernet_hdr *eth_header;     // struct ether_header 도 가능
    struct libnet_ipv4_hdr *ip_header;          // struct ip 도 가능
    u_short ip_header_bak[20];
    char *ip_header_ptr;
    struct libnet_tcp_hdr *tcp_header;          // struct tcphdr 도 가능
    u_char copy_packet[1500];
    u_char *copy_packet_p;

    unsigned short etherh_protocoltype;
    u_int8_t iph_protocol;
    uint16_t tcp_data_len;
    int length = pkthdr->len;

    memcpy(copy_packet, packet, 1500);    // 61 : "blocked" packet length
    copy_packet_p = copy_packet;
    // get ethernet header
    eth_header = (struct libnet_ethernet_hdr *)copy_packet;
    // get get ethernet header -> protocol type
    etherh_protocoltype = ntohs(eth_header->ether_type);

    if(etherh_protocoltype == ETHERTYPE_IP) {
        // move to offset
        copy_packet_p += sizeof(struct libnet_ethernet_hdr);
        packet += sizeof(struct libnet_ethernet_hdr);
        // get ip header
        ip_header = (struct libnet_ipv4_hdr *)copy_packet_p;
        iph_protocol = ip_header->ip_p;

        // move to next header offset
        copy_packet_p += sizeof(struct libnet_ipv4_hdr);
        packet += sizeof(struct libnet_ipv4_hdr);
        if(iph_protocol == IPPROTO_TCP) {
            // get tcp header
            tcp_header = (struct libnet_tcp_hdr *)copy_packet_p;

            copy_packet_p += (tcp_header->th_off)*4;
            packet += (tcp_header->th_off)*4;
            if(ntohs(tcp_header->th_dport) == 80) {
                if(strstr((char *)packet, "GET") != NULL) {
                    tcp_data_len = ntohs(ip_header->ip_len) - (ip_header->ip_hl + tcp_header->th_off)*4;    // tcp_data_len = [IP Total Length] - ([IP IHL] + [TCP Data offset])*4)
                    //printf("tcp data len : %d\n", tcp_data_len);
                    //printf("tcp_header->th_seq :%x\n", tcp_header->th_seq);

                    int redir_tcp_data_len;
                    if(menu == 2)
                        redir_tcp_data_len = strlen("blocked!");
                    else if(menu == 3)
                        redir_tcp_data_len = strlen("HTTP/1.1 302 Found\r\nLocation: http://gilgil.net/\r\n");

                    tcp_header->th_flags = TH_FIN | TH_ACK;
                    //tcp_header->th_flags = TH_RST;
                    int iphdr_total_len = sizeof(struct libnet_ipv4_hdr) + tcp_header->th_off*4 + redir_tcp_data_len;
                    ip_header->ip_len = htons(iphdr_total_len);
                    ip_header->ip_sum = 0;
                    if(menu == 1) {
                        tcp_header->th_seq = htonl(ntohl(tcp_header->th_seq) + tcp_data_len);
                    } else if(menu == 2 || menu == 3) {
                        uint8_t  tmp_mac[ETHER_ADDR_LEN];
                        struct in_addr tmp_ip;
                        uint16_t tmp_port;
                        uint32_t tmp_seq;
                        memcpy(tmp_mac, eth_header->ether_dhost, ETHER_ADDR_LEN);
                        memcpy(eth_header->ether_dhost, eth_header->ether_shost, ETHER_ADDR_LEN);
                        memcpy(eth_header->ether_shost, tmp_mac, ETHER_ADDR_LEN);
                        tmp_ip = ip_header->ip_src;
                        ip_header->ip_src = ip_header->ip_dst;
                        ip_header->ip_dst = tmp_ip;
                        tmp_port = tcp_header->th_sport;
                        tcp_header->th_sport = tcp_header->th_dport;
                        tcp_header->th_dport = tmp_port;
                        tmp_seq = tcp_header->th_seq;
                        tcp_header->th_seq = tcp_header->th_ack;
                        tcp_header->th_ack = htonl(ntohl(tmp_seq) + tcp_data_len);
                        tcp_header->th_sum = htons(0x00);

                    }
                    if(menu == 2)
                        memcpy(copy_packet_p, "blocked!", strlen("blocked!"));
                    else if(menu == 3)
                        memcpy(copy_packet_p, "HTTP/1.1 302 Found\r\nLocation: http://gilgil.net/\r\n", strlen("HTTP/1.1 302 Found\r\nLocation: http://gilgil.net/\r\n"));

                    // Caculate IP Checksum
                    ip_header_ptr = (char *)ip_header;
                    for(int i=0; i<sizeof(struct libnet_ipv4_hdr); i++)
                        ip_header_bak[i] = *(unsigned char *)ip_header_ptr++;
                    ip_header->ip_sum = htons(ip_checksum(20, ip_header_bak));

                    // Calculate TCP Checksum
                    compute_tcp_checksum((struct iphdr *)ip_header, (unsigned short *)tcp_header);
                    copy_packet_p = copy_packet_p - sizeof(struct libnet_ethernet_hdr) - sizeof(struct libnet_ipv4_hdr) - (tcp_header->th_off*4);
                    //print_data(copy_packet_p, iphdr_total_len+14);
                    printf(" - Url Detect~! Block Packet Send...\n");
                    if (pcap_sendpacket((pcap_t *)pcd, copy_packet_p, iphdr_total_len+14) != 0)
                    { fprintf(stderr,"\nError sending the packet(VtoG): %s\n", pcap_geterr((pcap_t *)pcd)); }
                }
            }
        }
    }
    //printf("\n");
}

int main(int argc, char **argv) {
    char track[] = "취약점";
    char name[] = "이우진";
    char *dev;
    char *net_str;
    char *mask_str;
    int ret;
    char errbuf[PCAP_ERRBUF_SIZE];
    bpf_u_int32 netp;
    bpf_u_int32 maskp;
    struct pcap_pkthdr hdr;
    struct in_addr net_addr, mask_addr;
    struct ether_header *eptr;
    const u_char *packet;

    struct bpf_program fp;

    pcap_t *pcd;    // packet capture descriptor

    printf("=====================================\n");
    printf("[bob5][%s]http_inject[%s]\n\n", track, name);
    // get network dev name("ens33")
    dev = pcap_lookupdev(errbuf);       // dev = "ens33"으로 해도 무방
    if(dev == NULL) { printf("%s\n", errbuf); exit(1); }
    printf("DEV: %s\n", dev);

    // get net, mask info
    ret = pcap_lookupnet(dev, &netp, &maskp, errbuf);
    if(ret == -1) { printf("%s\n", errbuf); exit(1); }

    // net, mask info to human_readable
    net_addr.s_addr = netp;
    net_str = inet_ntoa(net_addr);
    printf("NET : %s\n", net_str);

    mask_addr.s_addr = maskp;
    mask_str = inet_ntoa(mask_addr);
    printf("MASK : %s\n", mask_str);
    printf("=====================================\n");

    while(1) {
        printf("[*] Please Select Level~!!\n");
        printf("   1) FORWARD FIN (blocked)\n");
        printf("   2) BACKWARD FIN (blocked)\n");
        printf("   3) 302 redir FIN (blocked)\n\n");

        printf("   >> menu : ");
        scanf("%d", &menu);

        if((menu == 1) || (menu == 2) || (menu == 3)) break;
        else printf("Invalid Input~!\n\n");
    }

    pcd = pcap_open_live(dev, BUFSIZ, NONPROMISCUOUS, -1, errbuf);
    if(pcd == NULL) { printf("%s\n", errbuf); exit(1); }

    // filter option compile
    if(pcap_compile(pcd, &fp, "", 0, netp) == -1) {      //if(pcap_compile(pcd, &fp, "argv[2]", 0, netp) == -1) {
        printf("compile error\n");
        exit(1);
    }

    // filter option setting
    if(pcap_setfilter(pcd, &fp) == -1) {
        printf("setfilter error\n");
        exit(0);
    }

    pcap_loop(pcd, 0, packetfilter_callback, (u_char *)pcd);     //pcap_loop(pcd, atoi(argv[1]), packetfilter_callback, NULL);

    return 0;
}
