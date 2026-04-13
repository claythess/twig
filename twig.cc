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
#include "twig_packet_header.h"
#include "twig_print.h"


/* this normally comes from the pcap.h header file, but we'll just be using
 * a few specific pieces, so we'll add them here
 *
 * The first record in the file contains saved values for some
 * of the flags used in the printout phases of tcpdump.
 */



/* every pcap file starts with this structure */
struct pcap_file_header {
    bpf_u_int32 magic;
    u_short version_major;
    u_short version_minor;
    bpf_int32 thiszone;     /* gmt to local correction; this is always 0 */
    bpf_u_int32 sigfigs;    /* accuracy of timestamps; this is always 0 */
    bpf_u_int32 snaplen;    /* max length saved portion of each pkt */
    bpf_u_int32 linktype;   /* data link type (LINKTYPE_*) */
};

#define PCAP_MAGIC     0xa1b2c3d4
#define PCAP_VERSION_MAJOR 2
#define PCAP_VERSION_MINOR 4

/*
 * Generic per-packet information, as supplied by libpcap.
 * this is the second record in the file, and every packet starts
 * with this structure (followed by the packet date bytes)
 */



int debug;
std::fstream fh;
char* filename;


bool inverse_magic;

/*
 * the output should be formatted identically to this command:
 *   tshark -T fields -e frame.time_epoch -e frame.cap_len -e frame.len -e eth.dst -e eth.src -e eth.type  -r ping.dmp
 */

void swap_word(uint32_t &x){
    x = (x & 0x0000FFFF) << 16 | (x & 0xFFFF0000) >> 16;
    x = (x & 0x00FF00FF) << 8 | (x & 0xFF00FF00) >> 8;  
}

void swap_short(uint16_t &x){
    x = (x & 0x00FF) << 8 | (x & 0xFF00) >> 8;
}

int main(int argc, char *argv[])
{
    struct pcap_file_header pfh;
    //char *filename;
    
    /* start with something like this (or use this if you like it) */
    char* ip_interface = NULL;

    bool show_help = false;

    if (argc == 1){
        show_help = true;
    }

    for (int i = 1; i < argc; i++){
        if (strcmp(argv[i],"-d") == 0){
            debug = 1;
        }
        else if (strcmp(argv[i], "-i") == 0){
            if ((i + 1) < argc){
                ip_interface = argv[++i];
            }
            else{
                show_help = true;
            }
        }
        else{
            show_help = true;
        }
    }

    if (show_help){
        printf("Usage: ./twig [-hd] -i <interface>\n");
        exit(0);
    }

    uint32_t     ip_addr = 0;
    uint32_t net_ip_addr;

    uint32_t byte0;
    uint32_t byte1;
    uint32_t byte2;
    uint32_t byte3;
    uint32_t nmask;

    sscanf(ip_interface, "%u.%u.%u.%u_%u", &byte0, &byte1, &byte2, &byte3, &nmask);
    ip_addr = (byte0 << 24) | (byte1 << 16) | (byte2 << 8) | (byte3);
    
    if (debug) printf("%u\n", ip_addr);

    if (debug) printf("%u\n", nmask);

    uint nmask_bin = -1;
    nmask_bin = nmask_bin << (32 - nmask);
    if (debug) printf("%x\n", nmask_bin);
    net_ip_addr = ip_addr & nmask_bin;

    char* network_interface = (char*) malloc(sizeof(char) * 24);

    uint32_t nbyte0 = (net_ip_addr >> 24) & 255;
    uint32_t nbyte1 = (net_ip_addr >> 16) & 255;
    uint32_t nbyte2 = (net_ip_addr >>  8) & 255;
    uint32_t nbyte3 = (net_ip_addr >>  0) & 255;

    sprintf(network_interface,"%u.%u.%u.%u_%u.dmp", nbyte0, nbyte1, nbyte2, nbyte3, nmask);

    if (debug) printf("Netowrk: %s\n", network_interface);

    

    filename = network_interface;


    if (debug) printf("Trying to read from file '%s'\n", filename);

    /* now open the file (or if the filename is "-" make it read from standard input)*/
    std::fstream fh;
    fh.open(filename,std::fstream::in | std::fstream::out | std::fstream::binary);
    if (!fh.is_open()){
        perror(filename);
        exit(1);
    }

    /* read the pcap_file_header at the beginning of the file, check it, then print as requested */
    if (fh.read((char *)&pfh, sizeof(pfh)));
    else if (fh.eof()){
        printf("truncated pcap header: only %ld bytes\n", fh.gcount());
        exit(1);
    } /* need error checking */
    std::streamsize len = fh.gcount();

    //bool inverse_magic = false;

    if (debug)
    std::cout << "header chars read: " << len << std::endl;

    if (((pfh.magic) & 0xff) == 0xd4);
    else if (((pfh.magic) & 0xff) == 0xa1){
        inverse_magic = true;
        swap_word(pfh.magic);
        swap_short(pfh.version_major);
        swap_short(pfh.version_minor);
        swap_word(pfh.linktype);
    }
    else{
        printf("invalid magic number: 0x%08x\n", pfh.magic);
        exit(1);
    }
    


    printf("header magic: %x\n", pfh.magic);
    printf("header version: %d %d\n", pfh.version_major, pfh.version_minor);
    printf("header linktype: %d\n\n", pfh.linktype);
    /* now read each packet in the file */
    long unsigned int total_read;
    //std::streamsize last_read;
    while (1) {
        char frame_buffer[10000];
        char datagram_buffer[10000];

        /* read the pcap_packet_header, then print as requested */
        struct pcap_pkthdr pkh;
        total_read = 0;
        while (total_read < sizeof(pkh)){
            fh.clear();
            fh.read(((char *)&pkh) + total_read, sizeof(pkh) - total_read);
            total_read += fh.gcount(); 
        }
        /*
        else if (fh.eof()){
            if (fh.gcount() == 0) break;
            printf("truncated packet header: only %ld bytes\n", fh.gcount());
            exit(1);
        }*/ 

        len = fh.gcount();

        if (debug) printf("Packet chars read: %ld\n", len);

        if (inverse_magic){
            swap_word(pkh.ts_secs);
            swap_word(pkh.ts_usecs);
            swap_word(pkh.len);
            swap_word(pkh.caplen);
        //pkh.ts_secs = ntohl(pkh.ts_secs);
        //pkh.ts_usecs = ntohl(pkh.ts_usecs);
        }

        // Evil trailing zeros routine:
        char* timestamp = (char*) malloc(sizeof(char) * 22);
        memset(timestamp, 0, sizeof(char) * 22);
        sprintf(timestamp, "%10d.%06d", pkh.ts_secs, pkh.ts_usecs);
        for (int i = 19; i >= 0; i--){
            if (timestamp[i] == 0){
                timestamp[i] = '0';
            }
            else{
                break;
            }
        }

        if (debug) printf("%s\n", timestamp);
        /* then read the packet data that goes with it into a buffer (variable size) */

        //if () // doesn't work yet
        //int total_bytes = 0;
        if (pfh.linktype == 1) {
            /*
            if (fh.read(frame_buffer, sizeof(struct eth_hdr))){
                total_bytes += fh.gcount();
            }
            else if (fh.eof()){
                printf("truncated packet: only %d bytes\n", total_bytes);
                exit(1);
            }
            else {
                printf("Only Read %ld\n", fh.gcount());
                exit(1);
            }
                */
            total_read = 0;
            while (total_read < sizeof(struct eth_hdr)){
                fh.clear();
                fh.read((frame_buffer) + total_read, sizeof(struct eth_hdr) - total_read);
                total_read += fh.gcount(); 
            }

            struct eth_hdr *eth_hdr_ptr = (struct eth_hdr*) frame_buffer;
            
            
            
            // Read the IP Datagram
            
                
            int rest_of_packet_size = pkh.caplen - fh.gcount();

            
            if (debug) printf("Reading Rest of packet\n");
            /*
            if (fh.read(datagram_buffer, sizeof(char) * rest_of_packet_size));
            else if (fh.eof()){
                printf("truncated packet: only %ld bytes\n", total_bytes + fh.gcount());
                exit(1);
            }
            else{
                printf("error\n");
                exit(1);
            }
            */
            total_read = 0;
            while (total_read < sizeof(char) * rest_of_packet_size){
                fh.clear();
                fh.read((datagram_buffer) + total_read, (sizeof(char) * rest_of_packet_size) - total_read);
                total_read += fh.gcount(); 

            }
            


            printf("%s\t%d\t%d\t", timestamp, pkh.caplen, pkh.len);
            print_ethernet((struct eth_hdr *) frame_buffer);

            if ((eth_hdr_ptr -> eth_type[0] == 0x08) && (eth_hdr_ptr -> eth_type[1] == 0x00)){
                print_ipv4((struct ip_hdr*) datagram_buffer, ip_addr, (struct eth_hdr *) frame_buffer);
            }
            else if ((eth_hdr_ptr -> eth_type[0] == 0x08) && (eth_hdr_ptr -> eth_type[1] == 0x06)){
                print_arp((struct arp_hdr*) datagram_buffer);
            }
            std::fflush(0);


        }
        //break;   // to prevent infinite loop until you fix logic
    }
}