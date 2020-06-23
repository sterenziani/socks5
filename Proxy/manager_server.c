#include <stdio.h>
#include <stdlib.h>  // malloc
#include <string.h>  // memset
#include <assert.h>  // assert
#include <errno.h>
#include <signal.h>
#include <time.h>
#include <unistd.h>
#include <sys/socket.h>
#include <unistd.h>  // close
#include <pthread.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <netdb.h>
#include "request_manager_server.h"
#include "manager_server.h"
#include "buffer.h"
#include "stm.h"
#include "netutils.h"
#include "auth.h"


#define N(x) (sizeof(x)/sizeof((x)[0]))
#define MAX_BUFFER_SIZE 4096

static const struct state_definition* manager_server_describe_states(void);

unsigned int buffer_size;
uint8_t auth;
static bool done = false;

enum manager_server_state {
	MNG_SRV_HELLO_READ,
	MNG_SRV_HELLO_WRITE,
	MNG_SRV_REQUEST_READ,
	MNG_SRV_REQUEST_WRITE,
	DONE,
	ERROR,
};

struct hello_manager_server_st {
    buffer               *rb, *wb;
    struct auth_parser	parser;
    uint8_t               method;
};

struct request_manager_server_st {
    buffer               *rb, *wb;
    struct request_manager_server_parser parser;
};

static struct manager_server {

	union {
        struct hello_manager_server_st hello;
        struct request_manager_server_st request;
    } server;

	struct state_machine stm;
	enum manager_server_state state;

	struct sockaddr_storage socks_addr;
	socklen_t socks_addr_len;
	int socks_fd;

	char username[255];
  char password[255];

	uint8_t raw_buff_a[2048];
    uint8_t raw_buff_b[2048];
    buffer manager_server_read_buffer;
    buffer manager_server_write_buffer;
}manager_server_st;

static void manager_server_read   (struct selector_key *key);
static void manager_server_write  (struct selector_key *key);
static void manager_server_block  (struct selector_key *key);
static void manager_server_close  (struct selector_key *key);
static const struct fd_handler manager_server_handler = {
    .handle_read   = manager_server_read,
    .handle_write  = manager_server_write,
    .handle_close  = manager_server_close,
    .handle_block  = manager_server_block,
};

#define ATTACHMENT(key) ( (struct manager_server *)(key)->data)

static struct manager_server* new_manager_server(int manager_server_fd) {
	struct manager_server* server  = malloc(sizeof(*server));

	server->socks_fd = manager_server_fd;
	server->socks_addr_len = sizeof(server->socks_addr);


	server->state = MNG_SRV_HELLO_READ;

	server->stm.initial   = MNG_SRV_HELLO_READ;
  server->stm.max_state = ERROR;
  server->stm.states = manager_server_describe_states();

  stm_init(&server->stm);
  	
  buffer_init(&server->manager_server_read_buffer, N(server->raw_buff_a), server->raw_buff_a);
  buffer_init(&server->manager_server_write_buffer, N(server->raw_buff_b), server->raw_buff_b);

  return server;
}

void manager_server_start (struct  selector_key *key) {

  struct manager_server* state = NULL;

	struct sockaddr_storage socks_addr;
  socklen_t socks_addr_len = sizeof(socks_addr);

    const int manager = accept(key->fd, (struct sockaddr*) &socks_addr, &socks_addr_len);
    if(manager == -1) {
        goto fail;
    }
    if(selector_fd_set_nio(manager) == -1) {
        goto fail;
    }

    state = new_manager_server(manager);

    if(state == NULL) {
        goto fail;
    }
    memcpy(&state->socks_addr, &socks_addr, socks_addr_len);
    state->socks_addr_len = socks_addr_len;

    if(SELECTOR_SUCCESS != selector_register(key->s, manager, &manager_server_handler, OP_READ, state)) {
        goto fail;
    }

    return;
	
	fail:
    	if(manager != -1) {
        	close(manager);
    	}
}


/////////////////////////////////////////////////////////
//HELLO
/////////////////////////////////////////////////////////

static void hello_manager_server_write_init(const unsigned state, struct selector_key* key) {
    struct hello_manager_server_st *d = &ATTACHMENT(key)->server.hello;
    d->rb                              = &(ATTACHMENT(key)->manager_server_read_buffer);
    d->wb                              = &(ATTACHMENT(key)->manager_server_write_buffer);
}

static unsigned hello_manager_server_write(struct selector_key *key) {
  unsigned ret = 	MNG_SRV_REQUEST_READ;
  struct hello_manager_server_st *d = &ATTACHMENT(key)->server.hello;
  size_t  count;

  auth_marshall(d->wb, auth);

  uint8_t *ptr = buffer_read_ptr(d->wb, &count);
  if(ptr[1])
  {
    ret = ERROR;
  }

  if(count < 2) {
    ret = ERROR;
  }

  size_t n = send(key->fd, ptr, count, MSG_DONTWAIT);
  if(n != 2) {
    ret = ERROR;
  }

  if(n > 0) {
    buffer_read_adv(d->wb, n);
    if(SELECTOR_SUCCESS != selector_set_interest_key(key, OP_READ)) {
      ret = ERROR;
    }
  }
  return ret;
}

static void hello_manager_server_read_init(const unsigned state, struct selector_key *key) {
    struct hello_manager_server_st *d = &ATTACHMENT(key)->server.hello;
    d->rb                              = &(ATTACHMENT(key)->manager_server_read_buffer);
    d->wb                              = &(ATTACHMENT(key)->manager_server_write_buffer);
   	auth_parser_init(&d->parser);
}


static unsigned hello_manager_server_process(const struct hello_manager_server_st* d) {
    unsigned ret = 	MNG_SRV_HELLO_WRITE;
    auth = user_pass_valid(d->parser.username, d->parser.ulen, d->parser.password, d->parser.plen);
    return ret;
}

static unsigned hello_manager_server_read(struct selector_key *key) {
  struct hello_manager_server_st *d = &ATTACHMENT(key)->server.hello;
  struct manager_server *manager = ATTACHMENT(key);
  unsigned ret = MNG_SRV_HELLO_WRITE;
  bool error = false;
  uint8_t *ptr;
  size_t  count;
  ssize_t  n;
  ptr = buffer_write_ptr(d->rb, &count);
  n = recv(key->fd, ptr, count, 0);

  if(n > 0) {
      buffer_write_adv(d->rb, n);
      const enum auth_state st = auth_consume(d->rb, &d->parser, &error);

      if(auth_is_done(st, 0)) {
          ret = hello_manager_server_process(d);
          if(SELECTOR_SUCCESS == selector_set_interest_key(key, (1 << 2))) {
              if(ret == MNG_SRV_HELLO_WRITE)
              {
                memcpy(ATTACHMENT(key)->username, d->parser.username, d->parser.ulen);
                memcpy(ATTACHMENT(key)->password, d->parser.password, d->parser.plen);
              }
          } else {
              ret = ERROR;
          }
      }
  } else {
      ret = ERROR;
  }
  return error ? ERROR : ret;
}

/////////////////////////////////////////////////////////
//REQUEST
/////////////////////////////////////////////////////////

static void request_manager_server_write_init(const unsigned state, struct selector_key* key) {
    struct request_manager_server_st *d = &ATTACHMENT(key)->server.request;
    d->rb                              = &(ATTACHMENT(key)->manager_server_read_buffer);
    d->wb                              = &(ATTACHMENT(key)->manager_server_write_buffer);
}

static unsigned request_manager_server_write(struct selector_key* key) {
	struct request_manager_server_st *d = &ATTACHMENT(key)->server.request;
	unsigned ret = DONE;
    size_t  count;
    uint8_t *ptr = buffer_read_ptr(d->wb, &count);
    if(count < 3) {
      ret = ERROR;
    }

    size_t n = send(key->fd, ptr, count, MSG_DONTWAIT);

    if(n < 3) {
      ret = ERROR;
    }

    buffer_read_adv(d->wb, n);

    return ret;
}

static void request_manager_server_read_init(const unsigned state, struct selector_key *key) {
    struct request_manager_server_st *d = &ATTACHMENT(key)->server.request;
    d->rb                              = &(ATTACHMENT(key)->manager_server_read_buffer);
    d->wb                              = &(ATTACHMENT(key)->manager_server_write_buffer);
   	request_manager_server_parser_init(&d->parser);
}

static void unsigned_to_byte_converter(unsigned long number, uint8_t aux[], int size) {
  aux[0] = (uint8_t) number;
  for(int i = 1; i < size; i++) {
    aux[i] = (uint8_t) (number >> i*8);  
  }
  return;
}

static void request_manager_server_process(struct request_manager_server_st* d, struct selector_key *key, buffer *buff) {

  if(d->parser.command == 0x00) {
    	if(d->parser.user != NULL && d->parser.pass != NULL)
		    {	
		    	int i = 0;
		    	while(registered_users[i][0] != NULL && registered_users[i][1] != NULL && i<MAX_USERS) {
		    		i++;
		    	}

		    	if(i >= MAX_USERS) {
		    		request_marshall_change(buff, 0xFF, 0x00);
		    		return;
		    	}

		    	registered_users[i][0] = malloc(256*sizeof(char));
		    	memcpy(registered_users[i][0], d->parser.user, strlen((char *) d->parser.user));
		    	registered_users[i][1] = malloc(256*sizeof(char));
		    	memcpy(registered_users[i][1], d->parser.pass, strlen((char *) d->parser.pass));
		    	request_marshall_change(buff, 0x00, 0x00);

		    }
		}

	else if(d->parser.command == 0x01) {
		request_marshall_send_list(buff, registered_users);
	}

	else if(d->parser.command == 0x02) {
		uint8_t t_connections[8]; 
    unsigned_to_byte_converter(total_connections, t_connections, 8);
		uint8_t a_connections[4]; 
    unsigned_to_byte_converter(active_connections, a_connections, 4);
		uint8_t bytes_arr[8]; 
    unsigned_to_byte_converter(transferred_bytes, bytes_arr, 8);
		request_marshall_send_metrics(buff, t_connections, a_connections, bytes_arr);
	}

	else if(d->parser.command == 0x03) {
		max_clients = *((unsigned int*)(void*) d->parser.clients_size);
		request_marshall_change(buff, 0x00, 0x00);
	}

  else {
    fprintf(stdout, "Comando no aceptado");
    abort();
  }

}

static unsigned request_manager_server_read(struct selector_key *key) {
    struct request_manager_server_st *d = &ATTACHMENT(key)->server.request;
    unsigned  ret = MNG_SRV_REQUEST_WRITE;
    bool  error = false;
    uint8_t *ptr;
    size_t  count;
    ssize_t  n;

    ptr = buffer_write_ptr(d->rb, &count);
    n = recv(key->fd, ptr, count, 0);

    if(n > 0) {
        buffer_write_adv(d->rb, n);

        const enum request_manager_server_state st = request_manager_server_consume(d->rb, &d->parser, &error);

        if(request_manager_server_is_done(st, 0)) {
            if(SELECTOR_SUCCESS == selector_set_interest_key(key, (1 << 2))) {
                request_manager_server_process(d, key, d->wb);
            }
         	else
                ret = ERROR; 		
        }
    } else {
        ret = ERROR;
    }

    return error ? ERROR : ret;
}

static const struct state_definition manager_server_statbl[] = {

    {
      .state            = MNG_SRV_HELLO_READ,
      .on_arrival       = hello_manager_server_read_init,
      .on_read_ready    = hello_manager_server_read,
    },
    {
      .state            = MNG_SRV_HELLO_WRITE,
      .on_arrival       = hello_manager_server_write_init,
      .on_write_ready = hello_manager_server_write,
    },

    {
      .state            = MNG_SRV_REQUEST_READ,
      .on_arrival       = request_manager_server_read_init,
      .on_read_ready   	= request_manager_server_read,
    },
    {
      .state            = MNG_SRV_REQUEST_WRITE,
      .on_arrival       = request_manager_server_write_init,
      .on_write_ready   = request_manager_server_write,
    },
    {
      .state            = DONE,
      .on_arrival       = NULL,
      .on_departure     = NULL,
      .on_read_ready    = NULL,
    },
    {
      .state            = ERROR,
      .on_arrival       = NULL,
      .on_departure     = NULL,
      .on_read_ready    = NULL,
    }
};

static const struct state_definition* manager_server_describe_states(void) {
    return manager_server_statbl;
}



/////////////////////////////////////////////////////////
//HANDLERS
/////////////////////////////////////////////////////////

static void manager_server_done(struct selector_key* key);

static void manager_server_read(struct selector_key *key) {
    struct state_machine *stm   = &ATTACHMENT(key)->stm;
    const enum manager_server_state st = stm_handler_read(stm, key);

    struct manager_server* manager = ATTACHMENT(key);
    manager->state = st;

    if(ERROR == st || DONE == st)
    {
        if(ERROR == st)
        manager_server_done(key);
    }
}

static void manager_server_write(struct selector_key *key) {
    struct state_machine *stm   = &ATTACHMENT(key)->stm;
    const enum manager_server_state st = stm_handler_write(stm, key);

    struct manager_server* manager = ATTACHMENT(key);
    manager->state = st;

    if(ERROR == st || DONE == st) {
        manager_server_done(key);
    }
}

static void manager_server_block(struct selector_key *key) {
    struct state_machine *stm   = &ATTACHMENT(key)->stm;
    const enum manager_server_state st = stm_handler_block(stm, key);

    struct manager_server* manager = ATTACHMENT(key);
    manager->state = st;

    if(ERROR == st || DONE == st) {
        manager_server_done(key);
    }
}

static void manager_server_close(struct selector_key *key) {
}

static void manager_server_done(struct selector_key* key) {
    const int fds[] = {
        ATTACHMENT(key)->socks_fd,
    };
    for(unsigned i = 0; i < N(fds); i++)
    {
      if(fds[i] != -1 && fds[i] != 0) {
        if(SELECTOR_SUCCESS != selector_unregister_fd(key->s, fds[i]))
        {
          abort();
        }
        close(fds[i]);
      }
    }
}

