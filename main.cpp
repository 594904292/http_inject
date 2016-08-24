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

// Pseudo 헤더 구조체
struct pseudohdr
{
    struct in_addr ip_src, ip_dst; /* source and dest address */
    unsigned char reserved;
    uint8_t ip_p;                   /* protocol */
    unsigned short length;
    struct tcphdr tcpheader;
}__attribute__((packed));

int menu=0;

char *get_protocol_str(u_int8_t protocol) {
    char* protocol_type_str;

    switch(protocol) {
    case IPPROTO_ICMP:
        protocol_type_str = "ICMP";
        break;
    case IPPROTO_IGMP:
        protocol_type_str = "IGMP";
        break;
    case IPPROTO_TCP:
        protocol_type_str = "TCP";
        break;
    case IPPROTO_UDP:
        protocol_type_str = "UDP";
        break;
    default:
        protocol_type_str = "UNKNOWN";
        break;
    }

    return protocol_type_str;
}

char *get_tcp_flag_str(u_int8_t tcp_flags) {
    char *flags[9] = {"FIN","SYN","RST","PUSH","ACK","URG","ECE","CWR"};
    int flag_no[8] = {0,};
    static char tcp_flags_str[64]="";
    char tmp[10]="";
    int len;

    if(tcp_flags & TH_FIN) flag_no[0] = 1;
    if(tcp_flags & TH_SYN) flag_no[1] = 1;
    if(tcp_flags & TH_RST) flag_no[2] = 1;
    if(tcp_flags & TH_PUSH) flag_no[3] = 1;
    if(tcp_flags & TH_ACK) flag_no[4] = 1;
    if(tcp_flags & TH_URG) flag_no[5] = 1;
    if(tcp_flags & TH_ECE) flag_no[6] = 1;
    if(tcp_flags & TH_CWR) flag_no[7] = 1;

    tcp_flags_str[0] = '\0';
    for(int i=0; i<8; i++) {
        tmp[0] = '\0';
        if(flag_no[i] == 1) {
            strcat(tmp, flags[i]);
            strcat(tmp, " | ");
            strcat(tcp_flags_str, tmp);
        }
    }

    len = strlen(tcp_flags_str);
    tcp_flags_str[len-3] = '\0';
    return tcp_flags_str;
}

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
unsigned short tcp_checksum(unsigned short *buf, int len)
{
    register unsigned long sum = 0;

    while(len--)
        sum += *buf++;

    sum = (sum >> 16) + (sum & 0xffff);
    sum += (sum >> 16);

    return (unsigned short)(~sum);
}

void packetfilter_callback(u_char *pcd, const struct pcap_pkthdr *pkthdr, const u_char *packet) {
    static int count = 1;
    struct libnet_ethernet_hdr *eth_header;     // struct ether_header 도 가능
    struct libnet_ipv4_hdr *ip_header;          // struct ip 도 가능
    struct libnet_tcp_hdr *tcp_header;          // struct tcphdr 도 가능
    struct pseudohdr pseudo_hdr;
    //u_char copy_packet[73];
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

    printf("\n\n[Ethernet Packet info]\n");
    printf("   [*] Source MAC address : %s\n", ether_ntoa((const ether_addr *)eth_header->ether_shost));
    printf("   [*] Destination MAC address : %s\n", ether_ntoa((const ether_addr *)eth_header->ether_dhost));

    if(etherh_protocoltype == ETHERTYPE_IP) {
        // move to offset
        copy_packet_p += sizeof(struct libnet_ethernet_hdr);
        packet += sizeof(struct libnet_ethernet_hdr);
        // get ip header
        ip_header = (struct libnet_ipv4_hdr *)copy_packet_p;
        iph_protocol = ip_header->ip_p;

        printf("[IP Packet info]\n");
        printf("   [*] IP packet header length : %d bytes (%d)\n", ip_header->ip_hl*4, ip_header->ip_hl);
        printf("   [*] Next Layer Protocol Type : %s(0x%x)\n", get_protocol_str(iph_protocol), iph_protocol);
        printf("   [*] Source IP : %s\n", inet_ntoa(ip_header->ip_src));
        printf("   [*] Destination IP : %s\n", inet_ntoa(ip_header->ip_dst));

        // move to next header offset
        //copy_packet_p += ip_header->ip_hl * 4;
        copy_packet_p += sizeof(struct libnet_ipv4_hdr);
        packet += sizeof(struct libnet_ipv4_hdr);
        if(iph_protocol == IPPROTO_TCP) {
            // get tcp header
            tcp_header = (struct libnet_tcp_hdr *)copy_packet_p;

            printf("[TCP Packet info]\n");
            printf("   [*] Control Flag : %s\b\b\b\n", get_tcp_flag_str(tcp_header->th_flags));
            printf("   [*] Source Port : %d\n", ntohs(tcp_header->th_sport));
            printf("   [*] Destination Port : %d\n", ntohs(tcp_header->th_dport));
            printf("   [*] Data(HEX, ASCII)\n");
            //print_data(packet, length);

            //copy_packet_p += sizeof(struct libnet_tcp_hdr);
            //packet += sizeof(struct libnet_tcp_hdr);
            copy_packet_p += (tcp_header->th_off)*4;
            packet += (tcp_header->th_off)*4;
            if(ntohs(tcp_header->th_dport) == 80) {
                print_data(packet, length);
                if(strstr((char *)packet, "GET") != NULL) {
                    tcp_data_len = ntohs(ip_header->ip_len) - (ip_header->ip_hl + tcp_header->th_off)*4;    // tcp_data_len = [IP Total Length] - ([IP IHL] + [TCP Data offset])*4)
                    printf("tcp data len : %d\n", tcp_data_len);
                    printf("tcp_header->th_seq :%x\n", tcp_header->th_seq);

                    int redir_tcp_data_len = strlen("HTTP/1.1 302 Found\r\nLocation: http://warning.or.kr/\r\n");
                    tcp_header->th_flags = TH_FIN | TH_ACK;
                    //tcp_header->th_flags = TH_RST;
                    int iphdr_total_len = sizeof(struct libnet_ipv4_hdr) + tcp_header->th_off*4 + redir_tcp_data_len;
                    ip_header->ip_len = htons(iphdr_total_len);
                    if(menu == 1) {
                        tcp_header->th_seq = htonl(ntohl(tcp_header->th_seq) + tcp_data_len);
                        //tcp_header->th_flags = TH_FIN | TH_ACK; // FIN | ACK
                        //tcp_header->th_flags = TH_RST;
                        //int iphdr_total_len = sizeof(struct libnet_ipv4_hdr) + tcp_header->th_off*4 + 7;
                        //ip_header->ip_len = htons(iphdr_total_len);
                        //pseudo_hdr.ip_src.s_addr = ip_header->ip_src.s_addr;
                        //pseudo_hdr.ip_dst.s_addr = ip_header->ip_dst.s_addr;
                        //pseudo_hdr.ip_p = ip_header->ip_p;
                        //pseudo_hdr.length = htons(sizeof(struct libnet_tcp_hdr));
                        //memcpy(&pseudo_hdr.tcpheader, tcp_header, sizeof(struct libnet_tcp_hdr));
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
                    }
                    pseudo_hdr.ip_src.s_addr = ip_header->ip_src.s_addr;
                    pseudo_hdr.ip_dst.s_addr = ip_header->ip_dst.s_addr;
                    pseudo_hdr.ip_p = ip_header->ip_p;
                    pseudo_hdr.length = htons(sizeof(struct libnet_tcp_hdr));
                    memcpy(&pseudo_hdr.tcpheader, tcp_header, sizeof(struct libnet_tcp_hdr));


                    // calculate TCP checksum
                    tcp_header->th_sum = tcp_checksum((unsigned short *)&pseudo_hdr, sizeof(struct pseudohdr) / sizeof(unsigned short));
                    if(menu == 2) {
                        memcpy(copy_packet_p, "blocked", strlen("blocked"));
                    } else if(menu == 3) {
                        memcpy(copy_packet_p, "HTTP/1.1 302 Found\r\nLocation: http://warning.or.kr/\r\n", strlen("HTTP/1.1 302 Found\r\nLocation: http://warning.or.kr/\r\n"));
                    }
                    copy_packet_p = copy_packet_p - sizeof(struct libnet_ethernet_hdr) - sizeof(struct libnet_ipv4_hdr) - (tcp_header->th_off*4);
                    print_data(copy_packet_p, iphdr_total_len+14);
                    if (pcap_sendpacket((pcap_t *)pcd, copy_packet_p, iphdr_total_len+14) != 0)
                    { fprintf(stderr,"\nError sending the packet(VtoG): %s\n", pcap_geterr((pcap_t *)pcd));}
                }
            }
        }
        else {
            printf("[Unknown Packet]\n");
            printf("   [*] Not TCP Protocol ~~!\n");
            printf("   [*]    // TODO : other protocol handle");
        }
    }
    // IP 패킷이 아니라면
    else {
        printf("[Unknown Packet]\n");
        printf("   [*] Not IP Protocol ~~!\n");
        printf("   [*]    // TODO : other protocol handle");
    }
    printf("\n");
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
        printf("   3) 302 redir FIN (blocked)\n");

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
