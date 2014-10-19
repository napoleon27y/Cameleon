#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/uio.h>
#include <fcntl.h>
#include "kh_ca.h"

int fd, ret = 0;
off_t offset = 0;
char *temp_open;
char *temp_pointer;
char my_mac_addr_temp[7][3] = {0,};
char my_mac_addr_char[20] = {0,};
char my_ip_addr_temp[5][4] = {0,};
char my_ip_addr_char[20] = {0,};
char target_mac_addr_temp[7][3] = {0,};
char target_mac_addr_char[20] = {0,};
char *target_ip_addr_char[2] = {0,};
int my_mac_addr_int[6] = {0,};
int my_ip_addr_int[4] = {0,};
int target_mac_addr_int[2][6] = {0,};


void ARP_get_my_info()
{
  int i, j, k = 0;

  system( "mkdir /tmp/KH_CAMELEON 2> /dev/NULL" );

  //get my MAC address
  system( "cp /sys/class/net/eth0/address /tmp/KH_CAMELEON/my_mac_addr 2> /dev/NULL" );

  fd = open( "/tmp/KH_CAMELEON/my_mac_addr" , O_RDWR );
  if(fd < 0) { printf("err open (my_mac_addr)\n"); }

  offset = lseek( fd, (off_t)0, SEEK_END );
  lseek( fd, 0, SEEK_SET );

  ret = read( fd, my_mac_addr_char, offset );
  if(ret < 0) { printf("err read(my_mac_addr)\n"); }
  close( fd );

  for( i = 0; i < 6; i++ ) {
    for( j = 0; j < 2; j++ ) {
      if( my_mac_addr_char[k] == ':' ) { k++; }
      my_mac_addr_temp[i][j] = my_mac_addr_char[k];  k++;
    }
  }

  for( i = 0; i < 6; i++ ) {
    my_mac_addr_int[i] = ARP_change_mac_addr_to_decimal( my_mac_addr_temp[i] );
  }
 
 
  //get my ip address 
  system( "ifconfig 1> /tmp/KH_CAMELEON/ifconfig" );

  fd = open( "/tmp/KH_CAMELEON/ifconfig" , O_RDWR );
  if(fd < 0) { printf("err open(get_my_ip)\n"); }

  offset = lseek( fd, (off_t)0, SEEK_END );
  temp_open = (char *)calloc( offset, offset );
  lseek( fd, 0, SEEK_SET );

  ret = read( fd, temp_open, offset);
  if(ret < 0) { printf("err read(get_my_ip)\n"); }
  close( fd );

  temp_pointer = strstr( temp_open, "eth0" );
  strncpy( my_ip_addr_char, temp_pointer+78, 15 );
  free( temp_open );

  k = 0; j = 0;
  for( i = 0; i < 16; i++ ) {
    if( my_ip_addr_char[i] == '.' ) {
      k++; j = 0; my_ip_addr_temp[k][j] = my_ip_addr_char[i];
    } else { my_ip_addr_temp[k][j] = my_ip_addr_char[i]; j++; }
  }

  for( i = 0; i < 4; i++ ) {
    my_ip_addr_int[i] = atoi( my_ip_addr_temp[i] );
  }
}



void ARP_get_target_mac_addr( int argc, char *target )
{
  int i, j, k = 0;

  target_ip_addr_char[argc] = target; 

  //send ping
  char ping_cmd[40] = "ping -c 2                 1> /dev/NULL ";
  strncpy( ping_cmd+10, target_ip_addr_char[argc], strlen( target_ip_addr_char[argc] ) );
  system( ping_cmd );
  system( "cp /proc/net/arp /tmp/KH_CAMELEON/arp_log" );


  //read arp_cash_table
  fd = open( "/tmp/KH_CAMELEON/arp_log" , O_RDWR );
  if(fd < 0) { printf("err open(get_target_mac)\n"); }

  offset = lseek( fd, (off_t)0, SEEK_END );
  temp_open = (char *)calloc( offset, offset );
  lseek( fd, 0, SEEK_SET );

  ret = read( fd, temp_open, offset );
  if(ret < 0) { printf("err read(get_target_mac)\n"); }
  close( fd );


  //matching ip & MAC address

  int x = 0; 
  int y = 0;
  y = strlen(target_ip_addr_char[argc]);

  temp_pointer = strstr( temp_open, target_ip_addr_char[argc] );

  while( *(temp_pointer + y) != 0x20 ) { 
    temp_pointer = strstr( temp_open+x+y, target_ip_addr_char[argc] );
    x = temp_pointer-temp_open;

  } 

  strncpy( target_mac_addr_char, temp_pointer+41, 17 );

  free( temp_open );


  k = 0;
  for( i = 0; i < 6; i++ ) {
    for( j = 0; j < 2; j++ ) {
      if( target_mac_addr_char[k] == ':' ) { k++; }
      target_mac_addr_temp[i][j] = target_mac_addr_char[k]; k++;
    }
  }

  for( i = 0; i < 6; i++ ) {
    target_mac_addr_int[argc][i] = ARP_change_mac_addr_to_decimal_for_capital( target_mac_addr_temp[i] );
  }
}
