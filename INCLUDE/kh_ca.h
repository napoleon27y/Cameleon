#include <pcap.h>
#include <unistd.h>


/* DEFINE UTILITY FUNTION & HEADER */ 


int ARP_change_mac_addr_to_decimal( char num[] );

int ARP_change_mac_addr_to_decimal_for_capital( char num[] );

void Option( char *argv );




/* DEFINE ARP SPOOFING FUNTION & HEADER */ 


void ARP_get_my_info();

void ARP_get_target_mac_addr( int argc, char *target );

void ARP_send_reply();


typedef struct eth_hdr {
  unsigned char dst[6];
  unsigned char src[6];
  unsigned short type;
} __attribute__((packed)) ethdr;


typedef struct arp_hdr {
  unsigned short hwtype;
  unsigned short prtype;
  unsigned char hwsize; 
  unsigned char prsize;
  unsigned short opcode;
  unsigned char sender_mac_addr[6];
  unsigned int sender_ip_addr;
  unsigned char target_mac_addr[6];
  unsigned int target_ip_addr;
} __attribute__((packed)) arphdr;






/* DEFINE PCAP FUNCTION & HEADER */


int PCAP_packet_capture();

void process_packet( u_char *args, const struct pcap_pkthdr *header, const u_char *buffer );

void packet_forwarding( const u_char *Buffer, int Size);

void print_ethernet_header( const u_char *Buffer, int Size );

void print_ip_packet( const u_char *Buffer, int Size );

void print_tcp_packet( const u_char *Buffer, int Size );

void print_udp_packet( const u_char *Buffer, int Size );

void print_icmp_packet( const u_char *Buffer, int Size );




/* DEFINE SCAN FUNCTION & HEADER */


typedef struct ip_hdr {
  unsigned char hlen:4;
  unsigned char ver:4;
  unsigned char service;
  unsigned short total_len;
  unsigned short id;
  unsigned char flag;
  unsigned char offset;
  unsigned char ttl;
  unsigned char protocol;
  unsigned short checksum;
  unsigned int src;
  unsigned int dest;
} __attribute__((packed)) iphdr;


typedef struct TCP_hdr {
  unsigned short src_port;
  unsigned short dst_port;
  unsigned int seq;
  unsigned int ack;
  unsigned char unused:4;
  unsigned char hlen:4;
  unsigned char flag;
  unsigned short win;
  unsigned short checksum;
  unsigned short dummy;
} __attribute__((packed)) TCPhdr;


typedef struct pseudo_hdr {
  unsigned long int src;
  unsigned long int dst;
  unsigned char zero;
  unsigned char protocol;
  unsigned short length;
  struct TCP_hdr TCPhdr;
} __attribute__((packed)) pseudo;


struct server_list{
  char server_ip[16];
  char server_n[100];
};


unsigned short csum ( unsigned short *buf, int nwords );

void SCAN_get_network_if( char *network, char *subnet );

void SCAN_send_tcp_packet();

void SCAN_send_rst_packet( int port, int ack );

void SCAN_host_check( const u_char *Buffer, int Size );

void SCAN_port_check( const u_char *Buffer, int Size );

void Drdos_send();
