#ifndef SOCKS5_H
#define SOCKS5_H

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

#endif
