#ifndef DOH_H_
#define DOH_H_

/**
  * doh.c - resolvedor de nombres mediante doh
  *
*/

// includes
#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include "aux/buffer.h"

// funciones principales

// resuelve el nombre, estructura similar al getaddrinfo

// funciones auxiliares

// recibe un host y arma un dns message acorde en buffer
size_t
dnsEncode(const char* host, int dnsType, buffer *b, size_t buffSize);

#endif // DOH_H_
