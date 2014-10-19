#include <stdio.h>
#include <pcap.h>
#include <netinet/ip.h>
#include "kh_ca.h"


void process_packet( u_char *args, const struct pcap_pkthdr *header, const u_char *buffer )
{
  int size = header->len;
  extern int option_num;

  if( option_num == 1 || option_num == 2 ) {

    packet_forwarding( buffer, size );


  } else if( option_num == 3 ) {

    SCAN_host_check( buffer, size );


  } else if( option_num == 4 ) {

    SCAN_port_check( buffer, size );


  } else if( option_num == 5 ) {

    dns_filter(buffer);

    packet_forwarding( buffer, size );
  } 
}




void packet_forwarding( const u_char *Buffer, int Size )
{
  char errbuf[PCAP_ERRBUF_SIZE];
  pcap_t *handle;
  extern char *dev;
  extern int target_mac_addr_int[2][6];

  u_char *sniff_packet; 

  sniff_packet = (u_char *)Buffer;


  if( sniff_packet[6] == target_mac_addr_int[0][0] &&
      sniff_packet[7] == target_mac_addr_int[0][1] &&
      sniff_packet[8] == target_mac_addr_int[0][2] &&
      sniff_packet[9] == target_mac_addr_int[0][3] &&
      sniff_packet[10] == target_mac_addr_int[0][4] &&
      sniff_packet[11] == target_mac_addr_int[0][5] )
  {
    sniff_packet[0] = target_mac_addr_int[1][0];
    sniff_packet[1] = target_mac_addr_int[1][1];
    sniff_packet[2] = target_mac_addr_int[1][2];
    sniff_packet[3] = target_mac_addr_int[1][3];
    sniff_packet[4] = target_mac_addr_int[1][4];
    sniff_packet[5] = target_mac_addr_int[1][5];

  } else if( sniff_packet[6] == target_mac_addr_int[1][0] &&
             sniff_packet[7] == target_mac_addr_int[1][1] &&
             sniff_packet[8] == target_mac_addr_int[1][2] &&
             sniff_packet[9] == target_mac_addr_int[1][3] &&
             sniff_packet[10] == target_mac_addr_int[1][4] &&
             sniff_packet[11] == target_mac_addr_int[1][5] )
  {
    sniff_packet[0] = target_mac_addr_int[0][0];
    sniff_packet[1] = target_mac_addr_int[0][1];
    sniff_packet[2] = target_mac_addr_int[0][2];
    sniff_packet[3] = target_mac_addr_int[0][3];
    sniff_packet[4] = target_mac_addr_int[0][4];
    sniff_packet[5] = target_mac_addr_int[0][5];
  }

  handle = pcap_open_live( dev, 65536, 1, 0, errbuf );

  if( handle == NULL ) {
    printf( "Couldn't open device %s: %s\n", dev, errbuf );
  }

  if( pcap_sendpacket( handle, sniff_packet, Size ) != 0 ) { 
    printf( "Couldn't send packet for forwarding" );
  }

  pcap_close( handle );
}

 
 
