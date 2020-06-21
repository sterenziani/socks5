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
#include "hello_manager.h"
#include "request_manager.h"
#include "args_manager.h"
#include "manager.h"
#include "../Proxy/buffer.h"
#include "../Proxy/stm.h"
#include "../Proxy/netutils.h"

#define N(x) (sizeof(x)/sizeof((x)[0]))
#define MAX_BUFFER_SIZE 4096

static const struct state_definition* manager_describe_states(void);

unsigned int buffer_size;
struct manager_args* args;
static bool done = false;

enum manager_state {
	MNG_HELLO_WRITE,
	MNG_HELLO_READ,
	MNG_REQUEST_WRITE,
	MNG_REQUEST_READ,
	DONE,
	ERROR,
};

struct hello_manager_st {
    buffer               *rb, *wb;
    struct hello_manager_parser   parser;
    uint8_t               method;
};

struct request_manager_st {
    buffer               *rb, *wb;
    struct request_manager_parser parser;
};

static struct manager {

	union {
        struct hello_manager_st hello;
        struct request_manager_st request;
    } manager;

	struct state_machine stm;
	enum manager_state state;

	struct sockaddr_storage socks_addr;
	socklen_t socks_addr_len;
	int socks_fd;

	uint8_t raw_buff_a[2048];
    uint8_t raw_buff_b[2048];
    buffer manager_read_buffer;
    buffer manager_write_buffer;
}manager_st;

static void manager_read   (struct selector_key *key);
static void manager_write  (struct selector_key *key);
static void manager_block  (struct selector_key *key);
static void manager_close  (struct selector_key *key);
static const struct fd_handler manager_handler = {
    .handle_read   = manager_read,
    .handle_write  = manager_write,
    .handle_close  = manager_close,
    .handle_block  = manager_block,
};

#define ATTACHMENT(key) ( (struct manager *)(key)->data)

static struct manager* new_manager(int manager_fd) {
	struct manager* manager  = malloc(sizeof(*manager));

	manager->socks_fd = manager_fd;
	manager->socks_addr_len = sizeof(manager->socks_addr);

	manager->state = MNG_HELLO_WRITE;

	manager->stm.initial   = MNG_HELLO_WRITE;
  	manager->stm.max_state = ERROR;
  	manager->stm.states = manager_describe_states();
  	stm_init(&manager->stm);
  	
  	buffer_init(&manager->manager_read_buffer, N(manager->raw_buff_a), manager->raw_buff_a);
  	buffer_init(&manager->manager_write_buffer, N(manager->raw_buff_b), manager->raw_buff_b);

  	return manager;
}

void manager_start (struct  selector_key *key) {

	struct manager* state = NULL;

    fprintf(stdout, "MANAGER START\n");

	struct sockaddr_storage socks_addr;
    socklen_t socks_addr_len = sizeof(socks_addr);

    const int manager = accept(key->fd, (struct sockaddr*) &socks_addr, &socks_addr_len);
    if(manager == -1) {
        goto fail;
    }
    if(selector_fd_set_nio(manager) == -1) {
        goto fail;
    }

    state = new_manager(manager);

    if(state == NULL) {
        goto fail;
    }
    memcpy(&state->socks_addr, &socks_addr, socks_addr_len);
    state->socks_addr_len = socks_addr_len;

    if(SELECTOR_SUCCESS != selector_register(key->s, manager, &manager_handler, OP_WRITE, state)) {
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

static void hello_manager_write_init(const unsigned state, struct selector_key* key) {
    struct hello_manager_st *d = &ATTACHMENT(key)->manager.hello;
    d->rb                              = &(ATTACHMENT(key)->manager_read_buffer);
    d->wb                              = &(ATTACHMENT(key)->manager_write_buffer);
}

static unsigned hello_manager_write(struct selector_key* key) {
        fprintf(stdout, "MANAGER HELLO\n");

	struct hello_manager_st *d = &ATTACHMENT(key)->manager.hello;
	unsigned ret = MNG_HELLO_READ;
    size_t  count;
    uint8_t *ptr = buffer_write_ptr(d->wb, &count);
    if(count < 5) {
      ret = ERROR;
    }

    hello_manager_marshall(d->wb, (uint8_t*) args->auth.name, strlen(args->auth.name), (uint8_t*) args->auth.pass, strlen(args->auth.pass));

    size_t n = send(key->fd, ptr, count, MSG_DONTWAIT);
    if(n < 5) {
      ret = ERROR;
    }

    buffer_write_adv(d->wb, n);
    if(SELECTOR_SUCCESS != selector_set_interest_key(key, OP_READ)){
        ret = ERROR;
    }

    return ret;
}

static void hello_manager_read_init(const unsigned state, struct selector_key *key) {
    struct hello_manager_st *d = &ATTACHMENT(key)->manager.hello;
    d->rb                              = &(ATTACHMENT(key)->manager_read_buffer);
    d->wb                              = &(ATTACHMENT(key)->manager_write_buffer);
   	hello_manager_parser_init(&d->parser);
}

static unsigned hello_manager_read(struct selector_key *key) {
    struct hello_manager_st *d = &ATTACHMENT(key)->manager.hello;
    unsigned  ret = MNG_REQUEST_WRITE;
    bool  error = false;
    uint8_t *ptr;
    size_t  count;
    ssize_t  n;

    ptr = buffer_read_ptr(d->rb, &count);
    n = recv(key->fd, ptr, count, 0);

    if(n > 0) {
        buffer_read_adv(d->rb, n);

        const enum hello_manager_state st = hello_manager_consume(d->rb, &d->parser, &error);

        if(hello_manager_is_done(st, 0)) {
            if(SELECTOR_SUCCESS != selector_set_interest_key(key, OP_WRITE)) {
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

static void request_manager_write_init(const unsigned state, struct selector_key* key) {
    struct request_manager_st *d = &ATTACHMENT(key)->manager.request;
    d->rb                              = &(ATTACHMENT(key)->manager_read_buffer);
    d->wb                              = &(ATTACHMENT(key)->manager_write_buffer);
}

static unsigned request_manager_write(struct selector_key* key) {
	struct request_manager_st *d = &ATTACHMENT(key)->manager.request;
	unsigned ret = MNG_REQUEST_READ;
    size_t  count;
    uint8_t *ptr = buffer_write_ptr(d->wb, &count);
    if(count < 2) {
      ret = ERROR;
    }

    if(args->command == 0x00) {
    	request_marshall_new_user(d->wb, (uint8_t*) args->params.new_user.name, strlen(args->params.new_user.name), 
    		(uint8_t*) args->params.new_user.pass, strlen(args->params.new_user.pass));
    }

    else if(args->command == 0x01 || args->command == 0x02) {
    	request_marshall_get_info(d->wb, args->command);
    }

    else if(args->command == 0x03) {
    	request_marshall_change_pool(d->wb, args->params.new_pool_size);
    }

    else {
    	abort();
    }

    size_t n = send(key->fd, ptr, count, MSG_DONTWAIT);
    if(n < 2) {
      ret = ERROR;
    }

    buffer_write_adv(d->wb, n);
    if(SELECTOR_SUCCESS != selector_set_interest_key(key, OP_READ)){
        ret = ERROR;
    }

    return ret;
}

static void request_manager_read_init(const unsigned state, struct selector_key *key) {
    struct request_manager_st *d = &ATTACHMENT(key)->manager.request;
    d->rb                              = &(ATTACHMENT(key)->manager_read_buffer);
    d->wb                              = &(ATTACHMENT(key)->manager_write_buffer);
   	request_manager_parser_init(&d->parser);
}

static void request_manager_process(struct request_manager_st* d, struct selector_key *key) {
	if(args->command == 0x00) {
		fprintf(stdout, "Nuevo usuario agregado: %s\n", args->params.new_user.name);
	}
	else if(args->command == 0x01) {
		fprintf(stdout, "Usuarios actuales:\n");
		for(int i = 0; i < d->parser.user_number; i++) {
			fprintf(stdout, "%s", d->parser.users[i]);
		}
	}
/*
	else if(args->command == 0x02) {
		fprintf(stdout, "Conexiones historicas:		%ld\n"
		"Conexiones concurrentes:		%ld\n"
		"Bytes transferidos:		%ld\n", d->parser.total_con, d->parser.active_con, d->parser.bytes);
	}
*/
	else if(args->command == 0x03) {
		fprintf(stdout, "Nueva cantidad maxima de pool: %d\n", args->params.new_pool_size);
	}
}

static unsigned request_manager_read(struct selector_key *key) {
    struct request_manager_st *d = &ATTACHMENT(key)->manager.request;
    unsigned  ret = DONE;
    bool  error = false;
    uint8_t *ptr;
    size_t  count;
    ssize_t  n;

    ptr = buffer_read_ptr(d->rb, &count);
    n = recv(key->fd, ptr, count, 0);

    if(n > 0) {
        buffer_read_adv(d->rb, n);

        const enum request_manager_state st = request_manager_consume(d->rb, &d->parser, &error);

        if(request_manager_is_done(st, 0)) {
            if(SELECTOR_SUCCESS == selector_set_interest_key(key, OP_WRITE)) {
                request_manager_process(d, key);
            }
         	else
                ret = ERROR; 		
        }
    } else {
        ret = ERROR;
    }

    return error ? ERROR : ret;
}

static const struct state_definition manager_statbl[] = {
    {
      .state            = MNG_HELLO_WRITE,
      .on_arrival       = hello_manager_write_init,
      .on_write_ready	= hello_manager_write,
    },
    {
      .state            = MNG_HELLO_READ,
      .on_arrival       = hello_manager_read_init,
      .on_read_ready    = hello_manager_read,
    },
    {
      .state            = MNG_REQUEST_WRITE,
      .on_arrival       = request_manager_write_init,
      .on_write_ready   = request_manager_write,
    },
    {
      .state            = MNG_REQUEST_READ,
      .on_arrival       = request_manager_read_init,
      .on_read_ready   	= request_manager_read,
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

static const struct state_definition* manager_describe_states(void) {
    return manager_statbl;
}



/////////////////////////////////////////////////////////
//HANDLERS
/////////////////////////////////////////////////////////

static void manager_done(struct selector_key* key);

static void manager_read(struct selector_key *key) {
    struct state_machine *stm   = &ATTACHMENT(key)->stm;
    const enum manager_state st = stm_handler_read(stm, key);

    struct manager* manager = ATTACHMENT(key);
    manager->state = st;

    if(ERROR == st || DONE == st)
    {
        if(ERROR == st)
        manager_done(key);
    }
}

static void manager_write(struct selector_key *key) {
    struct state_machine *stm   = &ATTACHMENT(key)->stm;
    const enum manager_state st = stm_handler_write(stm, key);

    struct manager* manager = ATTACHMENT(key);
    manager->state = st;

    if(ERROR == st || DONE == st) {
        manager_done(key);
    }
}

static void manager_block(struct selector_key *key) {
    struct state_machine *stm   = &ATTACHMENT(key)->stm;
    const enum manager_state st = stm_handler_block(stm, key);

    struct manager* manager = ATTACHMENT(key);
    manager->state = st;

    if(ERROR == st || DONE == st) {
        manager_done(key);
    }
}

static void manager_close(struct selector_key *key) {
}

static void manager_done(struct selector_key* key) {
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
    fprintf(stdout, "Manager disconnected");
}


/////////////////////////////////////////////////////////
//MAIN
/////////////////////////////////////////////////////////

static void sigterm_handler(const int signal) {
    printf("signal %d, cleaning up and exiting\n",signal);
    done = true;
}

int main(const int argc, char **argv) {
    buffer_size = 2046;

    struct manager_args* args = malloc(sizeof(struct manager_args));
    parse_manager_args(argc, argv, args);

    // no tenemos nada que leer de stdin
    close(0);

    const char* err_msg = NULL;
    selector_status ss = SELECTOR_SUCCESS;
    fd_selector selector = NULL;

    // registrar sigterm es útil para terminar el programa normalmente.
    // esto ayuda mucho en herramientas como valgrind.
    signal(SIGTERM, sigterm_handler);
    signal(SIGINT,  sigterm_handler);

    const struct selector_init conf = {
        .signal = SIGALRM,
        .select_timeout = {
            .tv_sec  = 10,
            .tv_nsec = 0,
        },
    };

    if(0 != selector_init(&conf)) {
        err_msg = "initializing selector";
    }

    selector = selector_new(2);
    if(selector == NULL) {
        err_msg = "unable to create selector";
    }
    const struct fd_handler manager_fd_handler = {
        .handle_write  = manager_start,
        .handle_read   = NULL,
    	.handle_close  = NULL,
    	.handle_block  = NULL,
    };

    int sock;

    if(strchr(args->socks_addr, ':') == NULL) {
        struct sockaddr_in addr;
        memset(&addr, 0, sizeof(addr));
        addr.sin_family = AF_INET;
        addr.sin_addr.s_addr = inet_addr(args->socks_addr);
        addr.sin_port = htons(args->socks_port);
        sock = socket(AF_INET, SOCK_STREAM, 0);
        if(connect(sock, (struct sockaddr*) &addr, sizeof(addr)) == -1) {
    		fprintf(stderr, "No pudo conectarse al proxy\n");

    	}
    }
    else {
        struct sockaddr_in6 addr;
        memset(&addr, 0, sizeof(addr));
        addr.sin6_family = AF_INET6;
        inet_pton(AF_INET6, args->socks_addr, &addr.sin6_addr.s6_addr);
        addr.sin6_port = htons(args->socks_port);
        sock = socket(AF_INET6, SOCK_STREAM, 0);
        if(connect(sock, (struct sockaddr*) &addr, sizeof(addr)) == -1) {
    		fprintf(stderr, "No pudo conectarse al proxy\n");

    	}

    }


    ss = selector_register(selector, sock, &manager_fd_handler, OP_WRITE, NULL);
    if(ss != SELECTOR_SUCCESS) {
        err_msg = "registering fd";
    }

    for(;!done;) {
        err_msg = NULL;
        ss = selector_select(selector);
        if(ss != SELECTOR_SUCCESS) {
            err_msg = "serving";
            goto finally;
        }
    } 

    free(args);
    if(err_msg == NULL) {
        err_msg = "closing";
    }
    int ret = 0;

finally:
    if(ss != SELECTOR_SUCCESS) {
        fprintf(stderr, "%s: %s\n", (err_msg == NULL) ? "": err_msg, ss == SELECTOR_IO ? strerror(errno) : selector_error(ss));
        ret = 2;
    } else if(err_msg) {
        perror(err_msg);
        ret = 1;
    }
    if(selector != NULL) {
        selector_destroy(selector);
    }
    selector_close();

    if(sock >= 0) {
        close(sock);
    }
    return ret;
}

