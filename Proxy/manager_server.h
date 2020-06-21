#ifndef MANAGER_SERVER_H
#define MANAGER_SERVER_H

#ifdef __APPLE__
    #define MSG_DONTWAIT 0
#endif

#include <netdb.h>
#include "selector.h"

#define MAX_USERS 10

/** handler del socket pasivo que atiende conexiones socksv5 */
void socksv5_passive_accept(struct selector_key *key);

/** libera pools internos */
void socksv5_pool_destroy(void);

// variables extern
extern unsigned long total_connections;
extern unsigned int active_connections;
extern unsigned long transferred_bytes;
extern unsigned int max_clients;
extern bool disectors_enabled;
extern unsigned int buffer_size;
extern uint8_t pool_size;
extern struct doh* doh;

#endif