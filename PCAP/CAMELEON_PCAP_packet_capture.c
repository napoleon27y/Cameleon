#include <stdio.h>
#include <pcap.h>
#include "kh_ca.h"

char *dev;

int PCAP_packet_capture()
{
  char errbuf[PCAP_ERRBUF_SIZE];
  struct bpf_program fp;
  extern char filter_exp[40];
  bpf_u_int32 mask;
  bpf_u_int32 net;
  struct pcap_pkthdr header;
  pcap_t *handle;
  const u_char *packet;

  dev = pcap_lookupdev( errbuf );

  if( dev == NULL ) { 
    printf( "Couldn't find default device : %s\n", errbuf );
    return 2;
  }

  if( pcap_lookupnet( dev, &net, &mask, errbuf ) == -1 ) {
    printf( "Can't get netmask for device %s\n", dev );
    return 2;
  }

  handle = pcap_open_live( dev, 65536, 1, 0, errbuf );

  if( handle == NULL ) {
    printf( "Couldn't open device %s: %s\n", dev, errbuf );
    return 2;
  }
  
  if( pcap_datalink( handle ) != DLT_EN10MB ) { 
    printf( "Device %s dosen't provide Ethernet headers\n", dev );
    return 2;
  }

  if( pcap_setdirection( handle, PCAP_D_IN ) == -1 ) {
    printf( "Couldn't parase setdirection" );
    return 2;
  }

  if( pcap_compile( handle, &fp, filter_exp, 0, net ) == -1 ) {
    printf( "Couldn't parase filter %s: %s\n", filter_exp, pcap_geterr( handle ) );
    return 2;
  }

  if( pcap_setfilter( handle, &fp ) == -1 ) {
    printf( "Couldn't install filter %s: %s\n", filter_exp, pcap_geterr( handle ) );
    return 2;
  }

  pcap_loop( handle, -1, process_packet, NULL );

  return 0;
}
