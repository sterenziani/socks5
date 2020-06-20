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

#include "../args.h"
#include "../buffer.h"
#include "doh.h"
#include "parser_doh.h"

//defines
#define N(x) (sizeof(x)/sizeof((x)[0]))

#define BUFFER_MAX 1024
#define INT_STRING_MAX 11
#define TIMEOUT_SEC 5

// default dohServer
static struct doh defaultDoh = {
  .host   = "localhost",
  .ip     = "127.0.0.1",
  .port   = 8053,
  .path   = "/dns-query",
  .query  = "?dns=",
};

// doh_timeout time
static struct timespec doh_timeout = {
  .tv_sec = TIMEOUT_SEC,
  .tv_nsec = 0,
};


// funciones principales

// resuelve el nombre
size_t
solveDomain(const struct doh* dohAddr, const char* host, const char* port, struct addrinfo *hints, struct addrinfo **ret_addrInfo);

// funciones auxiliares

// recibe un sockadress y lo llena con los datos del servidor DOH, retorna 0 si el doh es válido, -1 caso contrario
int
getDohServer(const struct doh* dohAddr, struct sockaddr_storage* server);

// recibe un host y arma un dns message acorde en buffer
ssize_t
dnsEncode(const char* host, int dnsType, buffer *b, size_t buffSize);

// recibe la dirección de un doh server y un dns message y forma el request http
ssize_t
httpEncode(const struct doh* dohAddr, buffer *req, buffer *dnsMessage, char *contentLength);

// recibe un fd y un http-request, manda dicho request por el file descriptor
ssize_t
sendHttpMessage(int fd, buffer *request);

// manda todo lo readable del buffer al parser doh
int
feedParser(struct parser_doh *p, buffer *b);

void
freedohinfo(struct addrinfo *res);

#endif // DOH_H_
