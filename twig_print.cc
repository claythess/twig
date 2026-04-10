#include <stdlib.h>
#include <iostream>
#include <fcntl.h>
#include <unistd.h>
#include <netinet/in.h>
#include <cstring>
#include <fstream>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include "twig_packet_header.h"
#include "twig_print.h"

#include <sys/uio.h>

extern bool inverse_magic;
extern int debug;
extern std::fstream fh;
extern char* filename;


void print_mac(uint8_t* mac){
        for (int i = 0; i < 6; i++){
                printf("%02x",mac[i]);
                if (i != 5)
                        printf(":");
        }
}

void print_ethernet(struct eth_hdr *peh) {
        print_mac(peh -> dst_mac);
        printf("\t");
        print_mac(peh ->src_mac);
        printf("\t");
        printf("0x%02x", peh -> eth_type[0]);
        printf("%02x\n", peh -> eth_type[1]);
}



void print_ipv4_address(uint8_t address[]){
    for (int i = 0; i < 4; i++){
        printf("%d", address[i]);
        if (i != 3) printf(".");
    }
}


    
void print_dns(uint8_t address[]){
    printf("\t");

    struct hostent  *phe;

    phe = gethostbyaddr(address,4,AF_INET);
    if (phe != NULL) {
        printf("(%s)", phe -> h_name);
    }
}

void  handle_udp(struct udp_hdr* udp){
        printf("\tUDP:\tSport:\t%d\n", (udp -> src_port[0]<<8) | (udp->src_port[1]));
        printf("\t\tDport:\t%d\n", (udp -> dst_port[0]<< 8) | (udp->dst_port[1]));
        printf("\t\tDGlen:\t%d\n", (udp -> length[0]<<8) | (udp->length[1]));
        printf("\t\tCSum:\t%d\n", (udp -> chksum[0]<<8) | (udp->chksum[1]));
}

uint32_t fix_long(uint8_t old[]){
    uint32_t result = 0;
    for (int i = 0; i < 4; i++){
        uint32_t tmp = old[i];
        result = result | (tmp << ((3 - i) * 8));
    }
    return result;
}

void  handle_tcp(struct tcp_hdr *tcp){
    printf("\tTCP:\tSport:\t%d\n", (tcp -> src_port[0]<<8) | (tcp->src_port[1]));
    printf("\t\tDport:\t%d\n", (tcp -> dst_port[0]<< 8) | (tcp->dst_port[1]));
    printf("\t\tFlags:\t");
    char flag_str[] = "FSRPAU";
    uint8_t tmp = tcp -> flags;
    for (int i = 0; i < 6; i++){
        if (tmp & 1)
            printf("%c", flag_str[i]);
        else
            printf("-");
        tmp = tmp >> 1;            
    }
    uint32_t seq = ntohl(* (uint32_t *) tcp -> seq_num);
    uint32_t ack = ntohl(* (uint32_t *) tcp -> ack_num);
    

    printf("\n\t\tSeq:\t%u\n", seq);
    printf("\t\tACK:\t%u\n", ack);
    printf("\t\tWin:\t%u\n", (tcp -> window[0] << 8) | (tcp -> window[1]));
    printf("\t\tCSum:\t%d\n", (tcp -> chksum[0]<<8) | (tcp->chksum[1]));
}

void handle_icmp(struct icmp_hdr *icmp){
    
}


void print_ipv4(struct ip_hdr *ip, uint32_t local_addr, struct eth_hdr *parent_eth){
    printf("\tIP:\tVers:\t4\n");
    printf("\t\tHlen:\t%d bytes\n", (ip -> vers_ihl & 0xF)*4);
    printf("\t\tSrc:\t");
    print_ipv4_address(ip -> src);
    print_dns(ip -> src);
    printf("\n");
    printf("\t\tDest:\t");
    print_ipv4_address(ip -> dst);
    print_dns(ip -> dst);
    printf("\n");
    printf("\t\tTTL:\t%d\n", ip -> ttl);
    //printf("\t\tFrag Ident:\t%d\n", ip -> identification);
    printf("\t\tFrag Ident:\t%d\n", (((ip -> identification & 0x00FF) << 8) | ((ip -> identification & 0xFF00 )>> 8)));

    //* (uint16_t *) ip -> flags_fragment = ntohs( * (uint16_t *) ip -> flags_fragment);
    //printf("TMP : %x %x %d\n", ip -> flags_fragment[1], ip -> flags_fragment[0], inverse_magic);
    //uint16_t flag_frag = ntohs(* (uint16_t *) ip -> flags_fragment);
    //printf("%d\n", flag_frag & 0x1FFF);

    printf("\t\tFrag Offset:\t%d\n", (((ip ->flags_fragment[1] & 0xFF) << 3 ) | ((ip ->flags_fragment[0] & 0x1F) << 8) << 3));
    printf("\t\tFrag DF:\t");
    if (((ip -> flags_fragment[0] >> 6) & 1) == 1){
        printf("yes\n");
    }
    else{
        printf("no\n");
    }

    printf("\t\tFrag MF:\t");
    if (((ip -> flags_fragment[0] >> 5) & 1) == 1){
        printf("yes\n");
    }
    else{
        printf("no\n");
    }

    printf("\t\tIP CSum:\t%d\n", ((ip -> chksum >> 8) | (ip -> chksum << 8)) & 0xFFFF);
    printf("\t\tType:\t0x%x\t", ip -> protocol); // ?
    char* hdr = (char* ) ip;
    char* rest_of_packet = hdr + (ip -> vers_ihl & 0xF)*4;

    uint32_t ip_dst;
    uint8_t *dst = ip -> dst;
    uint32_t byte0, byte1, byte2, byte3;
    byte0 = dst[0];
    byte1 = dst[1];
    byte2 = dst[2];
    byte3 = dst[3];
    
    ip_dst = (byte0 << 24) | (byte1 << 16) | (byte2 << 8) | (byte3);

    if (ip -> protocol == 6){
        printf("(TCP)\n");
        // TCP
         handle_tcp((struct tcp_hdr*)rest_of_packet);
    }
    else if (ip -> protocol == 17){
        // UDP
        printf("(UDP)\n");
         handle_udp((struct udp_hdr*) rest_of_packet);
    }
    else if (ip -> protocol == 1){
        printf("(ICMP)\n");
        if (ip_dst == local_addr){
            printf("Handling ICMP\n");

            struct icmp_hdr* icmp = (struct icmp_hdr*) rest_of_packet;

            printf("%d %d\n", icmp -> type, icmp -> code);
            if (icmp -> type == 8 && icmp -> code == 0){
                printf("respond to ping\n");

                struct pcap_pkthdr pch;
                pch.caplen = sizeof(sizeof(struct ip_hdr) + sizeof(struct icmp_hdr));
                pch.len = sizeof(sizeof(struct ip_hdr) + sizeof(struct icmp_hdr));
                struct timeval tv;
                if (gettimeofday(&tv, NULL) == 0) {
                    pch.ts_secs = tv.tv_sec;
                    pch.ts_usecs = tv.tv_usec;
                }
                
                if (inverse_magic){
                    swap_word(pch.ts_secs);
                    swap_word(pch.ts_usecs);
                    swap_word(pch.len);
                    swap_word(pch.caplen);
                //pkh.ts_secs = ntohl(pkh.ts_secs);
                //pkh.ts_usecs = ntohl(pkh.ts_usecs);
                }

                struct eth_hdr eth;
                memcpy(eth.dst_mac, parent_eth->src_mac,sizeof(uint8_t) * 6);
                memcpy(eth.src_mac, parent_eth->dst_mac,sizeof(uint8_t) * 6);
                memcpy(eth.eth_type, parent_eth->eth_type,sizeof(uint8_t) * 2);

                struct ip_hdr iph;
                iph.protocol = 0;
                memcpy(&iph.dst, ip -> src, sizeof(uint8_t) * 4);
                memcpy(&iph.src, ip -> dst, sizeof(uint8_t) * 4);
                iph.total_length = sizeof(sizeof(struct ip_hdr) + sizeof(struct icmp_hdr));
                iph.ttl = 32;
                // iph.flags_fragment
                iph.vers_ihl = ip->vers_ihl; // Should be the same
                iph.total_length = ip->total_length; // should be the same
                iph.tos = ip->tos;
                iph.flags_fragment[0] = 0b01000000;
                iph.flags_fragment[1] = 0;
                iph.identification = rand();

                struct icmp_hdr response;
                response.type = 0;
                response.code = 0;
                response.rest = 0;
                response.chksum = 0;


                struct iovec iov[4];
                iov[0].iov_base = &pch;
                iov[0].iov_len = sizeof(struct pcap_pkthdr);

                iov[1].iov_base = &eth;
                iov[1].iov_len = sizeof(struct eth_hdr);

                iov[2].iov_base = &iph;
                iov[2].iov_len = sizeof(struct ip_hdr);

                iov[3].iov_base = &response;
                iov[3].iov_len = sizeof(icmp_hdr);
                
                //fh.write(reinterpret_cast<char*>(&pch), sizeof(pcap_pkthdr));
                //fh.write(reinterpret_cast<char*>(&iph), sizeof(ip_hdr));
                //fh.write(reinterpret_cast<char*>(&response), sizeof(icmp_hdr));
                
                int fd = open(filename, O_WRONLY | O_APPEND);
                writev(fd, iov, 4);
                close(fd);
            }
        }
    }
    else
        printf("\n");
}

void print_arp(struct arp_hdr *arp){
        printf("\tARP:\tHWtype:\t%d\n", arp->hardware_type[1]);
        printf("\t\thlen:\t%d\n", arp->hardware_length);
        printf("\t\tplen:\t%d\n", arp->protocol_length);
        printf("\t\tOP:\t%d ", arp->operation[1]);
        if (arp -> operation[1] == 1)
                printf("(ARP request)\n");
        if (arp -> operation[1] == 2)
                printf("(ARP reply)\n");
        
        printf("\t\tHardware:\t");
        print_mac(arp -> sender_hardware_address);
        printf("\n\t\t\t==>\t");
        print_mac(arp -> target_hardware_address);

        printf("\n\t\tProtocol:\t");
        print_ipv4_address(arp -> sender_protocol_address);
        printf("\t\n\t\t\t==>\t");
        print_ipv4_address(arp -> target_protocol_address);
        printf("\t\n");
}