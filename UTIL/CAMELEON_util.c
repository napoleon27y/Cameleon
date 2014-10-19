#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include "kh_ca.h"

int option_num = 0;
char filter_exp[40] = {0,};
extern char help[800];


void Option( char *argv )
{
  if( strcmp( argv, "-arp" ) == 0 ) { 
    option_num = 1; 
    sprintf( filter_exp, "arp" );

  } else if( strcmp( argv, "-ip" ) == 0 ) {
    option_num = 2;
    sprintf( filter_exp, "" );

  } else if( strcmp( argv, "-Hscn" ) == 0 ) { 
    option_num = 3; 
    sprintf( filter_exp, "tcp" );

  } else if( strcmp( argv, "-Pscn" ) == 0 ) { 
    option_num = 4; 
    sprintf( filter_exp, "tcp" );

  } else if( strcmp( argv, "-dns"  ) == 0 ) { 
    option_num = 5; 
    sprintf( filter_exp, "" );

  } else if( strcmp( argv, "-drdos" ) == 0 ) { 
    option_num = 6; 
    sprintf( filter_exp, "ip" );

  } else if( strcmp( argv, "--help" ) == 0 ) { 
    option_num = 7; 
    printf( "\n%s\n", help ); exit(0); 
  }
}




int ARP_change_mac_addr_to_decimal( char num[] )
{
    char char_set[17] = "x0123456789abcdef";
    int temp[2] = {0,};
    int i, j, k = 0;

    for( i = 0; i < 2; i++ ) {
        for( j = 0; j < 17; j++ ) {
            if( num[i] == char_set[j] ) { temp[i] = (j-1); }
        }
    }

    k = (temp[0]*16) + (temp[1]);

    return k;
}




int ARP_change_mac_addr_to_decimal_for_capital( char num[] )
{
    char char_set_capital[17] = "x0123456789ABCDEF";
    int temp[2] = {0,};
    int i, j, k = 0;

    for( i = 0; i < 2; i++ ) {
        for( j = 0; j < 17; j++ ) {
            if( num[i] == char_set_capital[j] ) { temp[i] = (j-1); }
        }
    }

    k = (temp[0]*16) + (temp[1]);

    return k;
}



unsigned short csum ( unsigned short *buf, int nwords )
{
  unsigned long sum;
  u_short oddbyte;
  register u_short answer;

  sum = 0;
  while( nwords > 1 ) {
  sum += *buf++;
  nwords -= 2;
  }

  if( nwords ==1 ) {
  oddbyte = 0;
  *((u_char *)&oddbyte) = *(u_char *)buf;
  sum += oddbyte;
  }
  sum = (sum >> 16) + (sum & 0xffff);

  sum += (sum >> 16);
  answer = ~sum;
  return (answer);
}
