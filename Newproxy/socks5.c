/**
 * socks5nio.c  - controla el flujo de un proxy SOCKSv5 (sockets no bloqueantes)
 */
#include<stdio.h>
#include <stdlib.h>  // malloc
#include <string.h>  // memset
#include <assert.h>  // assert
#include <errno.h>
#include <time.h>
#include <unistd.h>  // close
#include <pthread.h>

#include <arpa/inet.h>

#include "hello.h"
//#include "request.h"
#include "buffer.h"

#include "stm.h"
#include "socks5.h"
#include"netutils.h"

#define N(x) (sizeof(x)/sizeof((x)[0]))


/** maquina de estados general */
enum socks_v5state {
    /**
     * recibe el mensaje `hello` del cliente, y lo procesa
     *
     * Intereses:
     *     - OP_READ sobre client_fd
     *
     * Transiciones:
     *   - HELLO_READ  mientras el mensaje no esté completo
     *   - HELLO_WRITE cuando está completo
     *   - ERROR       ante cualquier error (IO/parseo)
     */
    HELLO_READ,

    /**
     * envía la respuesta del `hello' al cliente.
     *
     * Intereses:
     *     - OP_WRITE sobre client_fd
     *
     * Transiciones:
     *   - HELLO_WRITE  mientras queden bytes por enviar
     *   - REQUEST_READ cuando se enviaron todos los bytes
     *   - ERROR        ante cualquier error (IO/parseo)
     */
    HELLO_WRITE,

    //...

    // estados terminales
    DONE,
    ERROR,
};

////////////////////////////////////////////////////////////////////
// Definición de variables para cada estado

/** usado por HELLO_READ, HELLO_WRITE */
struct hello_st {
    /** buffer utilizado para I/O */
    buffer               *rb, *wb;
    struct hello_parser   parser;
    /** el método de autenticación seleccionado */
    uint8_t               method;
};

struct request_st {
    int a;
    // Que puedo necesitar aca???
};

struct copy {
  int a;
  // Que puedo necesitar aca???
};

struct connecting {
  int a;
  // Que puedo necesitar aca???
};

//...

/*
 * Si bien cada estado tiene su propio struct que le da un alcance
 * acotado, disponemos de la siguiente estructura para hacer una única
 * alocación cuando recibimos la conexión.
 *
 * Se utiliza un contador de referencias (references) para saber cuando debemos
 * liberarlo finalmente, y un pool para reusar alocaciones previas.
 */
struct socks5 {
    //...
    /** maquinas de estados */
    struct state_machine          stm;

    /** estados para el client_fd */
    union {
        struct hello_st           hello;
        struct request_st         request;
        struct copy               copy;
    } client;
    /** estados para el origin_fd */
    union {
        struct connecting         conn;
        struct copy               copy;
    } orig;

    struct sockaddr_storage client_addr;
    socklen_t client_addr_len;
    int client_fd;
    int origin_fd;
    struct addrinfo* origin_resolution;

    uint8_t raw_buff_a[2048];
    uint8_t raw_buff_b[2048];
    buffer client_read_buffer;
    buffer client_write_buffer;

    unsigned references;
    struct socks5* next;
};

static const unsigned max_pool = 50; // tamaño máximo
static unsigned pool_size = 0;  // tamaño actual
static struct socks5* pool = 0;  // pool propiamente dicho

static const struct state_definition* socks5_describe_states(void);

static struct socks5* socks5_new(int fd)
{
  struct socks5* ret;
  if(pool == NULL) {
      ret = malloc(sizeof(*ret));
  } else {
      ret       = pool;
      pool      = pool->next;
      ret->next = 0;
  }
  if(ret == NULL) {
      goto finally;
  }
  memset(ret, 0x00, sizeof(*ret));

  // Set the ret->thingies
  ret->client_fd = fd;
  buffer_init(&ret->client_read_buffer, N(ret->raw_buff_a), ret->raw_buff_a);
  buffer_init(&ret->client_write_buffer, N(ret->raw_buff_b), ret->raw_buff_b);
  ret->stm.initial   = HELLO_READ;
  ret->stm.max_state = ERROR;
  ret->stm.states = socks5_describe_states();
  stm_init(&ret->stm);
  ret->references = 1;

finally:
  return ret;
}

/** realmente destruye */
static void socks5_destroy_(struct socks5* s) {
    if(s->origin_resolution != NULL) {
        freeaddrinfo(s->origin_resolution);
        s->origin_resolution = 0;
    }
    free(s);
}

/**
 * destruye un  `struct socks5', tiene en cuenta las referencias
 * y el pool de objetos.
 */
static void socks5_destroy(struct socks5* s) {
    if(s == NULL) {
        // nada para hacer
    } else if(s->references == 1) {
        if(s != NULL) {
            if(pool_size < max_pool) {
                s->next = pool;
                pool = s;
                pool_size++;
            } else {
                socks5_destroy_(s);
            }
        }
    } else {
        s->references -= 1;
    }
}

void socksv5_pool_destroy(void) {
    struct socks5 *next, *s;
    for(s = pool; s != NULL ; s = next) {
        next = s->next;
        free(s);
    }
}

/** obtiene el struct (socks5 *) desde la llave de selección  */
#define ATTACHMENT(key) ( (struct socks5 *)(key)->data)

/* declaración forward de los handlers de selección de una conexión
 * establecida entre un cliente y el proxy.
 */
static void socksv5_read   (struct selector_key *key);
static void socksv5_write  (struct selector_key *key);
static void socksv5_block  (struct selector_key *key);
static void socksv5_close  (struct selector_key *key);
static const struct fd_handler socks5_handler = {
    .handle_read   = socksv5_read,
    .handle_write  = socksv5_write,
    .handle_close  = socksv5_close,
    .handle_block  = socksv5_block,
};

/** Intenta aceptar la nueva conexión entrante*/
void socksv5_passive_accept(struct selector_key *key) {
    struct sockaddr_storage client_addr;
    socklen_t client_addr_len = sizeof(client_addr);
    struct socks5* state = NULL;
    const int client = accept(key->fd, (struct sockaddr*) &client_addr, &client_addr_len);
    if(client == -1) {
        goto fail;
    }
    if(selector_fd_set_nio(client) == -1) {
        goto fail;
    }
    state = socks5_new(client);
    if(state == NULL) {
        // sin un estado, nos es imposible manejaro.
        // tal vez deberiamos apagar accept() hasta que detectemos
        // que se liberó alguna conexión.
        goto fail;
    }
    memcpy(&state->client_addr, &client_addr, client_addr_len);
    state->client_addr_len = client_addr_len;
    if(SELECTOR_SUCCESS != selector_register(key->s, client, &socks5_handler, OP_READ, state)) {
        goto fail;
    }
    return ;
fail:
    if(client != -1) {
        close(client);
    }
    socks5_destroy(state);
}

////////////////////////////////////////////////////////////////////////////////
// HELLO
////////////////////////////////////////////////////////////////////////////////

/** callback del parser utilizado en `read_hello' */
static void on_hello_method(struct hello_parser *p, const uint8_t method) {
    uint8_t *selected  = p->data;

    if(SOCKS_HELLO_NOAUTHENTICATION_REQUIRED == method) {
       *selected = method;
    }
}

/** inicializa las variables de los estados HELLO_... */
static void hello_read_init(const unsigned state, struct selector_key *key) {
    struct hello_st *d = &ATTACHMENT(key)->client.hello;
    d->rb                              = &(ATTACHMENT(key)->client_read_buffer);
    d->wb                              = &(ATTACHMENT(key)->client_write_buffer);
    d->parser.data                     = &d->method;
    d->parser.on_authentication_method = on_hello_method, hello_parser_init(&d->parser);
}

static void hello_write_init(const unsigned state, struct selector_key *key) {
    struct hello_st *d = &ATTACHMENT(key)->client.hello;
    d->rb                              = &(ATTACHMENT(key)->client_read_buffer);
    d->wb                              = &(ATTACHMENT(key)->client_write_buffer);
    buffer buf;
    uint8_t data[2] = {0};
    buffer_init(&buf, 2, data);

    if(hello_marshall(&buf, 0) != 2)
      abort();
    // El buffer contiene la respuesta
    //size_t bytesSent = send(key->client_fd, simple_buffer->simple_buffer + simple_buffer->from,bytesToSend,  MSG_DONTWAIT);
}

static unsigned hello_process(const struct hello_st* d);

/** lee todos los bytes del mensaje de tipo `hello' y inicia su proceso */
static unsigned hello_read(struct selector_key *key) {
    fprintf(stdout, "Entre al hello_read\n");
    struct hello_st *d = &ATTACHMENT(key)->client.hello; // key->client.hello.data = metodo
    unsigned  ret      = HELLO_READ;
        bool  error    = false;
     uint8_t *ptr;
      size_t  count;
     ssize_t  n;

    ptr = buffer_write_ptr(d->rb, &count);
    n = recv(key->fd, ptr, count, 0);
    fprintf(stdout, "n vale %ld\n", n);
    if(n > 0) {
        buffer_write_adv(d->rb, n);
        const enum hello_state st = hello_consume(d->rb, &d->parser, &error);
        fprintf(stdout, "st devuelto por hello_consume vale %d\n", st);
        if(hello_is_done(st, 0)) {
            fprintf(stdout, "hello_is_done(st, 0) es true\n");
            if(SELECTOR_SUCCESS == selector_set_interest_key(key, OP_WRITE)) {
                fprintf(stdout, "selector_set_interest_key devolvio SUCCESS\n");
                ret = hello_process(d);
            } else {
                fprintf(stdout, "selector_set_interest_key salio mal :(\n");
                ret = ERROR;
            }
        }
    } else {
        ret = ERROR;
    }

    return error ? ERROR : ret;
}

/** procesamiento del mensaje `hello' */
static unsigned hello_process(const struct hello_st* d) {
    unsigned ret = HELLO_WRITE;

    uint8_t m = d->method;
    const uint8_t r = (m == SOCKS_HELLO_NO_ACCEPTABLE_METHODS) ? 0xFF : 0x00;
    if (-1 == hello_marshall(d->wb, r)) {
        ret  = ERROR;
    }
    if (SOCKS_HELLO_NO_ACCEPTABLE_METHODS == m) {
        ret  = ERROR;
    }
    return ret;
}

static void hello_read_close(const unsigned state, struct selector_key *key){
  fprintf(stdout, "Estoy en hello_read_close\n");
}

/** definición de handlers para cada estado */
static const struct state_definition client_statbl[] = {
    {
        .state            = HELLO_READ,
        .on_arrival       = hello_read_init,
        .on_departure     = hello_read_close,
        .on_read_ready    = hello_read,
    },
    {
      .state            = HELLO_WRITE,
      .on_arrival       = hello_write_init, // On arrival debería enviarle el reponse con el método. Está en d->data
      .on_departure     = NULL,
      .on_read_ready    = NULL,
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

static const struct state_definition* socks5_describe_states(void) {
    return client_statbl;
}

///////////////////////////////////////////////////////////////////////////////
// Handlers top level de la conexión pasiva.
// son los que emiten los eventos a la maquina de estados.
static void socksv5_done(struct selector_key* key);

static void socksv5_read(struct selector_key *key) {
    struct state_machine *stm   = &ATTACHMENT(key)->stm;
    const enum socks_v5state st = stm_handler_read(stm, key);

    if(ERROR == st || DONE == st)
    {
        if(ERROR == st)
          fprintf(stdout, "st is ERROR %d\n", st);
        socksv5_done(key);
    }
}

static void socksv5_write(struct selector_key *key) {
    struct state_machine *stm   = &ATTACHMENT(key)->stm;
    const enum socks_v5state st = stm_handler_write(stm, key);

    if(ERROR == st || DONE == st) {
        socksv5_done(key);
    }
}

static void socksv5_block(struct selector_key *key) {
    struct state_machine *stm   = &ATTACHMENT(key)->stm;
    const enum socks_v5state st = stm_handler_block(stm, key);

    if(ERROR == st || DONE == st) {
        socksv5_done(key);
    }
}

static void socksv5_close(struct selector_key *key) {
    socks5_destroy(ATTACHMENT(key));
}

static void socksv5_done(struct selector_key* key) {
      fprintf(stdout, "Hola\n");
    const int fds[] = {
        ATTACHMENT(key)->client_fd,
        ATTACHMENT(key)->origin_fd,
    };
    for(unsigned i = 0; i < N(fds); i++)
    {
        if(fds[i] != -1) {
            if(SELECTOR_SUCCESS != selector_unregister_fd(key->s, fds[i]))
            {
                fprintf(stdout, "ABORTANDO AL INGENIERO\n");
                abort();
            }
            close(fds[i]);
        }
    }
}
