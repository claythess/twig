#pragma once
#include <stdlib.h>
#include <iostream>
#include <fcntl.h>
#include <unistd.h>
#include <netinet/in.h>
#include <cstring>
#include <fstream>

#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>

typedef int32_t bpf_int32;
typedef u_int32_t bpf_u_int32;

struct pcap_pkthdr {
    bpf_u_int32 ts_secs;        /* time stamp */
    bpf_u_int32 ts_usecs;   /* time stamp */
    bpf_u_int32 caplen;     /* length of portion present */
    bpf_u_int32 len;    /* length of this packet (off wire) */
};

struct eth_hdr {
    /* create this structure */
        uint8_t dst_mac[6];
        uint8_t src_mac[6];
        uint8_t eth_type[2];
};

struct ip_hdr {
        uint8_t vers_ihl; // split
        uint8_t tos; // garbage
        uint16_t total_length;
        uint16_t identification;
        uint8_t flags_fragment[2]; // split
        uint8_t ttl;
        uint8_t protocol;
        uint16_t chksum;
        uint8_t src[4];
        uint8_t dst[4];


};

struct arp_hdr {
        uint8_t hardware_type[2];
        uint8_t protocol_type[2];
        uint8_t hardware_length;
        uint8_t protocol_length;
        uint8_t operation[2];
        uint8_t sender_hardware_address[6];
        uint8_t sender_protocol_address[4];
        uint8_t target_hardware_address[6];
        uint8_t target_protocol_address[4];
};

struct tcp_hdr{
        uint8_t src_port[2];
        uint8_t dst_port[2];
        uint8_t seq_num[4];
        uint8_t ack_num[4];
        uint8_t offset;
        uint8_t flags;
        uint8_t window[2];
        uint8_t chksum[2];
        uint8_t urgent_ptr[2];
};

struct udp_hdr {
        uint8_t src_port[2];
        uint8_t dst_port[2];
        uint8_t length[2];
        uint8_t chksum[2];
};

struct icmp_hdr {
        uint8_t type;
        uint8_t code;
        uint16_t chksum;
        uint32_t rest;
};