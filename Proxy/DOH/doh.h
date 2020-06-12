#ifndef DOH_H_
#define DOH_H_

/**
  * doh.c - resolvedor de nombres mediante doh
  *
*/

// includes
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/select.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <netinet/in.h>

#include "../buffer.h"
#include "doh.h"
#include "parser_doh.h"

//defines

// defines relacionados con el doh server
#define ADDRESS_PORT 8080
#define ADDRESS "127.0.0.1"
#define ADDRESS_TYPE AF_INET

// otros defines
#define N(x) (sizeof(x)/sizeof((x)[0]))

#define BUFFER_MAX 1024
#define INT_STRING_MAX 11
#define TIMEOUT_SEC 5

// funciones principales

// resuelve el nombre
size_t
solveDomain(const char* host, int dnsType, struct addrinfo **ret_addrInfo);

// funciones auxiliares

// recibe un sockadress y lo llena con los datos del servidor DOH
void
getDohServer(struct sockaddr_in* server);

// recibe un host y arma un dns message acorde en buffer
size_t
dnsEncode(const char* host, int dnsType, buffer *b, size_t buffSize);

// recibe la dirección de un doh server y un dns message y forma el request http
size_t
httpEncode(char* doh, buffer *req, buffer *dnsMessage, char *contentLength);

// recibe un fd y un http-request, manda dicho request por el file descriptor
size_t
sendHttpMessage(int fd, buffer *request);

// manda todo lo readable del buffer al parser doh
int
feedParser(struct parser_doh *p, buffer *b);

#endif // DOH_H_
