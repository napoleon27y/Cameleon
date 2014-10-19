#include <stdio.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include "kh_ca.h"

int net_h, sub_h, Bcast, Bcast_host_num;

void SCAN_get_network_if( char *network, char *subnet )
{
  char *gateway;
  char *Target[1] = {0,};
  struct in_addr addr;
  extern option_num;

  if( option_num == 3 ) { 

    net_h = ntohl( inet_addr( network ) );
    sub_h = ntohl( inet_addr( subnet ) );

    addr.s_addr = inet_addr( subnet );

    Bcast_host_num = ( 0xff - inet_lnaof( addr ) );
    Bcast = net_h + Bcast_host_num;

    addr.s_addr = htonl( net_h+1 );
    gateway = inet_ntoa( addr ); 

    Target[0] = gateway;

    ARP_get_target_mac_addr( 0, Target[0] );
  }
}

