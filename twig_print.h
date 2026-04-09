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

extern bool inverse_magic;
extern int debug;
extern std::fstream fh;
extern char* filename;

void print_mac(uint8_t* mac);
void print_ethernet(struct eth_hdr *peh);
void print_ipv4_address(uint8_t address[]);
void print_dns(uint8_t address[]);
void print_udp(struct udp_hdr* udp);
uint32_t fix_long(uint8_t old[]);
void print_tcp(struct tcp_hdr *tcp);
void print_ipv4(struct ip_hdr *ip, uint32_t local_addr);
void print_arp(struct arp_hdr *arp);

void swap_word(uint32_t &x);
void swap_short(uint16_t &x);
