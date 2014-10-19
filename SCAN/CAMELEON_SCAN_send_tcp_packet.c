#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <net/if.h>
#include <net/if_arp.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include "kh_ca.h"


void SCAN_send_tcp_packet()
{
  int i, count, port, sock = 0;
  struct sockaddr_ll sll;
  extern option_num;
  extern int net_h, sub_h, Bcast, Bcast_host_num;
  extern int my_mac_addr_int[6];
  extern int target_mac_addr_int[2][6];
  extern char *target_ip_addr_char[2];
  extern char my_ip_addr_char[20];

  ethdr         eth;
  iphdr         ip;
  TCPhdr        TCP;
  pseudo        pseudo;

  bzero( &sll, sizeof( sll ) );
  sll.sll_family = PF_PACKET;
  sll.sll_ifindex = if_nametoindex( "eth0" );
  sll.sll_halen = 6;

  sleep(3);

  sock = socket( PF_PACKET, SOCK_RAW, 0 );

  if( option_num == 3 ) { count = Bcast_host_num; } 
  else if( option_num == 4 ) { count = 0xffff; }

  for( i = 0; i < count; i++ ) {

    eth.dst[0] = target_mac_addr_int[0][0];
    eth.dst[1] = target_mac_addr_int[0][1];
    eth.dst[2] = target_mac_addr_int[0][2];
    eth.dst[3] = target_mac_addr_int[0][3];
    eth.dst[4] = target_mac_addr_int[0][4];
    eth.dst[5] = target_mac_addr_int[0][5];

    eth.src[0] = my_mac_addr_int[0];
    eth.src[1] = my_mac_addr_int[1];
    eth.src[2] = my_mac_addr_int[2];
    eth.src[3] = my_mac_addr_int[3];
    eth.src[4] = my_mac_addr_int[4];
    eth.src[5] = my_mac_addr_int[5];

    eth.type = htons( 0x0800 );

    ip.ver = 0x04;
    ip.hlen = sizeof( ip ) >> 2;
    ip.service = 0x00;
    ip.total_len = htons( sizeof( ip ) + sizeof( TCP ) );
    ip.id = htons(0x0001);
    ip.flag = 0x00;
    ip.offset = 0x00;
    ip.ttl = 0x40;
    ip.protocol = 0x06;
    ip.checksum = 0x00;
    ip.src = inet_addr( my_ip_addr_char );

    if( option_num == 3 ) { 
      ip.dest = htonl( net_h + i ); 
      TCP.dst_port = htons( 50000 );
      TCP.flag = 0x12;

    } else if( option_num == 4 ) {
      ip.dest = inet_addr( target_ip_addr_char[0] );
      TCP.dst_port = htons( i );
      TCP.flag = 0x02;
    }

    ip.checksum = csum( (unsigned short *)&ip, sizeof( ip ) );

    TCP.src_port = htons( 10001 );
    TCP.seq = htonl(0x12345678);
    TCP.ack = htonl(0x00);
    TCP.unused = 0x00;
    TCP.hlen = sizeof( TCP ) >> 2;
    TCP.win = htons ( 65535 );
    TCP.checksum = 0x00;
    TCP.dummy = 0x00;

    pseudo.src = ip.src; 
    pseudo.dst = ip.dest;
    pseudo.zero = 0x00;
    pseudo.protocol = ip.protocol;
    pseudo.length = htons( sizeof( TCP ) );
    memcpy( &pseudo.TCPhdr, &TCP, sizeof( TCP ) );
 
    TCP.checksum = csum( (unsigned short *)&pseudo, sizeof( pseudo ) );

    char gData[ sizeof( ethdr ) + sizeof( iphdr ) + sizeof( TCPhdr ) ];
  
    memcpy( gData, &eth, sizeof( eth ) );
    memcpy( gData + sizeof( eth ), &ip, sizeof( ip ) );
    memcpy( gData + sizeof( eth ) + sizeof( ip ), &TCP, sizeof( TCP ) );
  
    sendto( sock, gData, sizeof( eth ) + sizeof( ip ) + sizeof( TCP ), 
                            0, (struct sockaddr *)&sll, sizeof( sll ) );

  }
}

