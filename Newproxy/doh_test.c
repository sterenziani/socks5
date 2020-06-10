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
#include "buffer.h"
#include "doh.h"

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
  struct buffer message;
  buffer *m = &message;
  uint8_t direct_buff_m[BUFFER_MAX];
  buffer_init(&message, N(direct_buff_m), direct_buff_m);

  size_t result = solveDomain(HOST,DNS_TYPE,m);
  assert(result==0);
  printf("doh_test/connect: success!\n");

  return;
}
