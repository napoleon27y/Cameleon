#include <pcap.h>

void dns_filter(const u_char *buffer);

void dns_send_reply(unsigned short td, u_int16_t dport, unsigned int d_src);

typedef struct eth_hdr {
  unsigned char dst[6];
  unsigned char src[6];
  unsigned short type;
} __attribute__((packed)) Gethdr;

typedef struct ip_hdr {
unsigned char hlen:4;
unsigned char ver:4;
unsigned char service;
unsigned short total;
unsigned short id;
unsigned char flag;
unsigned char offset;
unsigned char ttl;
unsigned char protocol;
unsigned short chk;
unsigned int src;
unsigned int dst;
} __attribute__((packed)) Giphdr;

typedef struct dns_hdr {
  unsigned short tid;
  unsigned short flag;
  unsigned short questions;
  unsigned short answer;
  unsigned short authority;
  unsigned short add;
  unsigned char name[15];
  unsigned short type;
  unsigned short class;
  unsigned short ans_name;
  unsigned short ans_type;
  unsigned short ans_class;
  unsigned int ans_ttl;
  unsigned short ans_dlen;
  unsigned int ans_addr;

} __attribute__((packed)) Gdnshdr;

typedef struct pseudo_hdr {
unsigned long int src;
unsigned long int dst;
unsigned char zero;
unsigned char protocol;
unsigned short length;
struct udphdr udp;
Gdnshdr dns;
}__attribute__((packed)) Gpseudohdr;
