#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <pcap.h>
#include <net/ethernet.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include "kh_ca.h"

int total = 0;


void SCAN_host_check( const u_char *Buffer, int Size )
{
  unsigned short iphdrlen;
  struct sockaddr_in source;
  struct iphdr *iph = (struct iphdr *)(Buffer + sizeof(struct ethhdr));
  iphdrlen = iph->ihl*4;

  struct tcphdr *tcph = (struct tcphdr *)(Buffer + iphdrlen + sizeof(struct ethhdr) );

  if( iph->protocol == 6 && tcph->rst == 1 ) { 

    memset(&source, 0, sizeof(source));
    source.sin_addr.s_addr = iph->saddr;
  
    usleep(500000); total++;

    printf( "  %d. %s\n", total, inet_ntoa(source.sin_addr) );
  }
}



void SCAN_port_check( const u_char *Buffer, int Size )
{
  unsigned short iphdrlen;
  struct iphdr *iph = (struct iphdr *)(Buffer + sizeof(struct ethhdr));
  iphdrlen = iph->ihl*4;

  struct tcphdr *tcph = (struct tcphdr *)(Buffer + iphdrlen + sizeof(struct ethhdr) );

  if( iph->protocol == 6 && tcph->syn == 1 && tcph->ack == 1 ) {

    usleep(500000); total++;

    printf( "  %d. Port : %d\n", total, ntohs( tcph->source ) );

    SCAN_send_rst_packet( tcph->source, tcph->seq ); 
  }
}

