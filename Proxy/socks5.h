#ifndef SOCKS5_H
#define SOCKS5_H

#ifdef __APPLE__
    #define MSG_DONTWAIT 0
#endif

#include <netdb.h>
#include "selector.h"

// METRICS
typedef struct metrics_struct{
  long concurrent_conections;
  long historic_conections;
  long bytes_transfered;
} metrics_struct;

typedef metrics_struct * metrics_t;

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

#endif
