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

#include "../Proxy/args.h"
#include "../Proxy/buffer.h"
#include "../Proxy/DOH/doh.h"

#define TIMEOUT_SEC 5

//test variable
#define HOST "www.google.com."
#define PORT "80"

#define N(x) (sizeof(x)/sizeof((x)[0]))
#define BUFFER_MAX 1024
#define INT_STRING_MAX 11

// test functions
void test_ipv4(void);
void test_ipv6(void);
void test_unspec(void);

int main(int argc, char *argv[])
{
  test_ipv4();
  test_ipv6();
  test_unspec();
  return 0;
}

void test_ipv4(void){
  struct addrinfo hints;
  struct addrinfo *res_doh,*aux;
  int sockfd;

  memset(&hints, 0, sizeof hints);
	hints.ai_family = AF_INET;
	hints.ai_socktype = SOCK_STREAM;

  ssize_t result = solveDomain(NULL,HOST,PORT,&hints,&res_doh);
  assert(result==0);
  printf("doh_test/returns_ipv4:\tsuccess!\n");

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

  aux = res_doh;
  while(aux!=NULL && aux->ai_family!=AF_INET && aux->ai_family!=AF_INET6){
    aux = aux->ai_next;
  }

  assert(aux!=NULL);
  assert(aux->ai_family==AF_INET);

  sockfd = socket(aux->ai_family,aux->ai_socktype,0);

  assert(connect(sockfd,aux->ai_addr,aux->ai_addrlen) == 0);
  printf("doh_test/connect_ipv4:\tsuccess!\n");

  shutdown(sockfd, SHUT_RDWR);
  freedohinfo(res_doh);

  return;
}

void test_ipv6(void){
  struct addrinfo hints;
  struct addrinfo *res_doh,*aux;
  int sockfd;

  memset(&hints, 0, sizeof hints);
  // IPv6

  hints.ai_family = AF_INET6;
  ssize_t result = solveDomain(NULL,HOST,PORT,&hints,&res_doh);
  assert(result==0);
  printf("doh_test/returns_ipv6:\tsuccess!\n");

  aux = res_doh;
  while(aux!=NULL && aux->ai_family!=AF_INET && aux->ai_family!=AF_INET6){
    aux = aux->ai_next;
  }

  assert(aux!=NULL);
  assert(aux->ai_family==AF_INET6);
  assert(aux->ai_socktype==SOCK_STREAM);

  sockfd = socket(aux->ai_family,aux->ai_socktype,0);

  assert( connect(sockfd,aux->ai_addr,aux->ai_addrlen)==0 || errno ==65 );
  if(errno==65){
    printf("doh_test/connect_ipv6: unknown, no ipv6 support\n");
  }else{
    printf("doh_test/connect_ipv6:\tsuccess!\n");
  }

  shutdown(sockfd, SHUT_RDWR);
  freedohinfo(res_doh);

  return;
}

void test_unspec(void){
  struct addrinfo hints;
  struct addrinfo *res_doh,*aux;
  int sockfd;

  memset(&hints, 0, sizeof hints);

  hints.ai_family = AF_UNSPEC;
  ssize_t result = solveDomain(NULL,HOST,PORT,&hints,&res_doh);
  assert(result==0);
  printf("doh_test/returns_unspec:\tsuccess!\n");

  aux = res_doh;
  while(aux!=NULL && aux->ai_family!=AF_INET && aux->ai_family!=AF_INET6){
    aux = aux->ai_next;
  }

  assert(aux!=NULL);
  assert(aux->ai_family==AF_INET || aux->ai_family==AF_INET6);
  assert(aux->ai_socktype==SOCK_STREAM);

  sockfd = socket(aux->ai_family,aux->ai_socktype,0);

  assert( connect(sockfd,aux->ai_addr,aux->ai_addrlen)==0 || errno ==65 );
  if(errno==65){
    printf("doh_test/connect_unspec: unknown, no ipv6 support\n");
  }else{
    printf("doh_test/connect_unspec:\tsuccess!\n");
  }

  shutdown(sockfd, SHUT_RDWR);
  freedohinfo(res_doh);

  return;
}
