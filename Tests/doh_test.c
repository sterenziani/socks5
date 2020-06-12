/*
** doh_test.c -- tries to make a http request
* currently has all functions that doh.c should have
*/

#include <assert.h>
#include <stdlib.h>
#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>

#include "../Proxy/buffer.h"
#include "../Proxy/DOH/doh.h"

#define TIMEOUT_SEC 5

//test variable
#define HOST "itba.edu.ar"
#define DNS_TYPE AF_INET
#define PORT 80

#define N(x) (sizeof(x)/sizeof((x)[0]))
#define BUFFER_MAX 1024
#define INT_STRING_MAX 11

// test functions
void test_returns(void);

int main(int argc, char *argv[])
{
  test_returns();
  return 0;
}

void test_returns(void){
  struct addrinfo *res_doh;
  int sockfd;

  size_t result = solveDomain(HOST,DNS_TYPE,&res_doh);
  assert(result==0);
  printf("doh_test/connect:\tsuccess!\n");

  struct addrinfo *aux = res_doh;
  while(aux!=NULL){
    ((struct sockaddr_in*)aux->ai_addr)->sin_port = htons(PORT);
    aux = aux->ai_next;
  }

  // dejando getaddrinfo para la forma tradicional
  /*
  struct addrinfo *res_dns;
  struct addrinfo hints;
  hints.ai_family = AF_INET;
  hints.ai_socktype = SOCK_STREAM;
  getaddrinfo(HOST, "80", &hints, &res_dns);
  */

  // estas pruebas eran muy engorrosas y tenian la posibilidad de que fallen
  //printf("%u\n",(unsigned) ((struct sockaddr_in*)res_doh->ai_addr)->sin_addr.s_addr);
  //printf("%u\n",(unsigned) ((struct sockaddr_in*)res_dns->ai_addr)->sin_addr.s_addr);
  //printf("%u\n",(unsigned) ((struct sockaddr_in*)res_doh->ai_next->ai_addr)->sin_addr.s_addr);
  //printf("%u\n",(unsigned) ((struct sockaddr_in*)res_dns->ai_next->ai_addr)->sin_addr.s_addr);

  sockfd = socket(AF_INET,SOCK_STREAM,0);

  assert(connect(sockfd,res_doh->ai_addr,res_doh->ai_addrlen) == 0);
  printf("doh_test/can_connect_to_returned_address:\tsuccess!\n");

  shutdown(sockfd, SHUT_RDWR);

  return;
}
