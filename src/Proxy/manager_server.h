#ifndef MANAGER_SERVER_H
#define MANAGER_SERVER_H

#ifdef __APPLE__
    #define MSG_DONTWAIT 0
#endif

#include <netdb.h>
#include "selector.h"

#define MAX_USERS 10
#define MAX_CLIENTS 505

void manager_server_start (struct  selector_key *key);


// variables extern
extern unsigned long total_connections;
extern unsigned int active_connections;
extern unsigned long transferred_bytes;
extern unsigned int max_clients;
extern bool disectors_enabled;
extern unsigned int buffer_size;
extern unsigned int max_clients;

#endif
