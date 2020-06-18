/**
 * socks5nio.c  - controla el flujo de un proxy SOCKSv5 (sockets no bloqueantes)
 */
#include <stdio.h>
#include <stdlib.h>  // malloc
#include <string.h>  // memset
#include <assert.h>  // assert
#include <errno.h>
#include <time.h>
#include <sys/socket.h>
#include <unistd.h>  // close
#include <pthread.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include "hello.h"
#include "auth.h"
#include "request.h"
#include "buffer.h"
#include "stm.h"
#include "socks5.h"
#include "netutils.h"
#include "passwords.h"
#include "base64.h"
#include "DOH/doh.h"
#define N(x) (sizeof(x)/sizeof((x)[0]))
#define MAX_BUFFER_SIZE 4096

extern int total_connections;
extern int active_connections;
extern unsigned long transferred_bytes;
extern int max_clients;

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

        /**
     * recibe el mensaje request del cliente, y lo procesa
     *
     * Intereses:
     *     - OP_READ sobre client_fd
     *
     * Transiciones:
     *   - REQUEST_READ  mientras el mensaje no esté completo
     *   - REQUEST_WRITE cuando está completo
     *   - ERROR       ante cualquier error (IO/parseo)
     */

    AUTH_READ,
    AUTH_WRITE,
    REQUEST_READ,
    REQUEST_RESOLVE,

    /**
     * envía la respuesta del request al cliente.
     *
     * Intereses:
     *     - OP_WRITE sobre client_fd
     *
     * Transiciones:
     *   - RESPONSE_WRITE  mientras queden bytes por enviar
     *   - DONE cuando se enviaron todos los bytes
     *   - ERROR        ante cualquier error (IO/parseo)
     */
    REQUEST_WRITE,


    COPY,

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

struct auth_st {
    /** buffer utilizado para I/O */
    buffer               *rb, *wb;
    struct auth_parser   parser;
};

struct request_st {
    /** buffer utilizado para I/O */
    buffer               *rb, *wb;
    struct request_parser  parser;
};

struct copy_st {
  buffer               *rb, *wb;
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
        struct auth_st            auth;
        struct request_st         request;
        struct copy_st            copy;
    } client;
    /** estados para el origin_fd */
    union {
        struct copy_st               copy;
    } orig;

    struct sockaddr_storage client_addr;
    socklen_t client_addr_len;
    int client_fd;
    int origin_fd;

    // ORIGIN
    struct addrinfo* origin_resolution;
    char origin_addr[255];
    int origin_port;
    struct sockaddr_storage origin_addr_storage;

    union{
      struct http_parser http;
      struct pop3_parser pop3;
    } parser;

    uint8_t communication_buffer_a[2048];
    uint8_t communication_buffer_b[2048];
    buffer client_read_buffer;
    buffer client_write_buffer;

    uint8_t communication_buffer_x[2048];
    uint8_t communication_buffer_y[2048];
    buffer origin_read_buffer;
    buffer origin_write_buffer;

    char username[255];
    char password[255];
    bool needed_resolve;
    unsigned references;
    struct socks5* next;
    bool active;
};

static const unsigned max_pool = 50;
static unsigned pool_size = 0;
static struct socks5* pool = 0;

static const struct state_definition* socks5_describe_states(void);

static struct socks5* socks5_new(int fd)
{
  if(active_connections >= max_clients)
  {
    fprintf(stdout, "Connection rejected. Maximum client capacity surpassed.\n");
    return NULL;
  }
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
  ret->client_fd = fd;
  buffer_init(&ret->client_read_buffer, N(ret->communication_buffer_a), ret->communication_buffer_a);
  buffer_init(&ret->client_write_buffer, N(ret->communication_buffer_b), ret->communication_buffer_b);
  buffer_init(&ret->origin_read_buffer, N(ret->communication_buffer_x), ret->communication_buffer_x);
  buffer_init(&ret->origin_write_buffer, N(ret->communication_buffer_y), ret->communication_buffer_y);
  ret->stm.initial   = HELLO_READ;
  ret->stm.max_state = ERROR;
  ret->stm.states = socks5_describe_states();
  stm_init(&ret->stm);
  ret->references = 1;
  ret->active = true;
  ret->needed_resolve = false;

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
              if(s->active)
              {
                s->active = false;
                s->next = pool;
                pool = s;
                pool_size++;
              }
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
    active_connections++;
    total_connections++;
    memcpy(&state->client_addr, &client_addr, client_addr_len);
    state->client_addr_len = client_addr_len;
    if(SELECTOR_SUCCESS != selector_register(key->s, client, &socks5_handler, OP_READ, state)) {
        goto fail;
    }
    return;
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
    if(SOCKS_HELLO_USER_PASS_AUTHENTICATION == method) {
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
}

static unsigned hello_write(struct selector_key *key) {
    struct hello_st *d = &ATTACHMENT(key)->client.hello;
    unsigned ret = REQUEST_READ;
    size_t  count;
    uint8_t *ptr = buffer_read_ptr(d->wb, &count);
    if(ptr[1] == SOCKS_HELLO_USER_PASS_AUTHENTICATION)
    {
      ret = AUTH_READ;
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

static unsigned hello_process(const struct hello_st* d);

/** lee todos los bytes del mensaje de tipo `hello' y inicia su proceso */
static unsigned hello_read(struct selector_key *key) {
    struct hello_st *d = &ATTACHMENT(key)->client.hello;
    unsigned  ret      = HELLO_WRITE;
        bool  error    = false;
     uint8_t *ptr;
      size_t  count;
     ssize_t  n;
    ptr = buffer_write_ptr(d->rb, &count);
    n = recv(key->fd, ptr, count, 0);
    if(n > 0) {
        buffer_write_adv(d->rb, n);
        const enum hello_state st = hello_consume(d->rb, &d->parser, &error);
        if(hello_is_done(st, 0)) {
            if(SELECTOR_SUCCESS == selector_set_interest_key(key, OP_WRITE)) {
                d->method = *((uint8_t*) d->parser.data);
                ret = hello_process(d);
            } else {
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
    uint8_t r;
    if(m == SOCKS_HELLO_NO_ACCEPTABLE_METHODS)
      r = METHOD_NO_ACCEPTABLE_METHODS;
    else if(m == SOCKS_HELLO_USER_PASS_AUTHENTICATION)
      r = METHOD_USER_PASS_AUTHENTICATION;
    else
      r = METHOD_NO_AUTHENTICATION_REQUIRED;

    if (-1 == hello_marshall(d->wb, r)) {
        ret  = ERROR;
    }
    if (SOCKS_HELLO_NO_ACCEPTABLE_METHODS == m) {
        ret  = ERROR;
    }
    return ret;
}

static void hello_read_close(const unsigned state, struct selector_key *key){
}

static void hello_write_close(const unsigned state, struct selector_key *key){
}

////////////////////////////////////////////////////////////////////////////////
// AUTH
////////////////////////////////////////////////////////////////////////////////

static void auth_read_init(const unsigned state, struct selector_key *key) {
    struct auth_st *d = &ATTACHMENT(key)->client.auth;
    d->rb                              = &(ATTACHMENT(key)->client_read_buffer);
    d->wb                              = &(ATTACHMENT(key)->client_write_buffer);
    auth_parser_init(&d->parser);
}

static unsigned auth_process(const struct auth_st* d) {
    unsigned ret = AUTH_WRITE;
    uint8_t m = user_pass_valid(d->parser.username, d->parser.ulen, d->parser.password, d->parser.plen);
    if (-1 == auth_marshall(d->wb, m)) {
        ret  = ERROR;
    }
    return ret;
}

static unsigned auth_read(struct selector_key *key) {
  struct auth_st *d = &ATTACHMENT(key)->client.auth;
  unsigned ret = AUTH_WRITE;
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
          if(SELECTOR_SUCCESS == selector_set_interest_key(key, OP_WRITE)) {
              ret = auth_process(d);
              if(ret == AUTH_WRITE)
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

static unsigned auth_write(struct selector_key *key) {
  unsigned ret = REQUEST_READ;
  struct auth_st *d = &ATTACHMENT(key)->client.auth;
  size_t  count;
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

////////////////////////////////////////////////////////////////////////////////
// REQUEST
////////////////////////////////////////////////////////////////////////////////
static void request_read_init(const unsigned state, struct selector_key *key) {
    struct request_st *d = &ATTACHMENT(key)->client.request;
    d->rb                              = &(ATTACHMENT(key)->client_read_buffer);
    d->wb                              = &(ATTACHMENT(key)->client_write_buffer);
    request_parser_init(&d->parser);
}

static void request_write_init(const unsigned state, struct selector_key *key) {
    struct request_st *d = &ATTACHMENT(key)->client.request;
    d->rb                              = &(ATTACHMENT(key)->client_read_buffer);
    d->wb                              = &(ATTACHMENT(key)->client_write_buffer);
    return;
}

static unsigned request_write(struct selector_key *key) {
    struct request_st *d = &ATTACHMENT(key)->client.request;
    struct socks5 *sock = ATTACHMENT(key);
    unsigned ret = COPY;
    size_t  count;
    uint8_t len, fam;
    if(sock->origin_addr_storage.ss_family == AF_INET6)
    {
      len = 16;
      fam = ipv6;
    }
    else
    {
      fam = ipv4;
      len = 4;
    }
    if(request_marshall(d->wb, fam, (uint8_t*)((const struct sockaddr *) &sock->origin_addr_storage)->sa_data+2, (uint8_t*)((const struct sockaddr *) &sock->origin_addr_storage)->sa_data, len) < 10)
    {
      abort();
    }
    uint8_t *ptr = buffer_read_ptr(d->wb, &count);
    if(count < 10) {
      abort();
    }
    size_t n = send(sock->client_fd, ptr, count, MSG_DONTWAIT);
    if(n < 10) {
      abort();
    }

    if(sock->needed_resolve){
      if(n > 0) {
        buffer_read_adv(d->wb, n);
        if(SELECTOR_SUCCESS != selector_set_interest(key->s, sock->client_fd, OP_READ)){
          ret = ERROR;
        }
        if(SELECTOR_SUCCESS != selector_set_interest(key->s, sock->origin_fd, OP_READ)){
          ret = ERROR;
        }
      }
    }
    else{
      if(n > 0) {
        buffer_read_adv(d->wb, n);
        if(SELECTOR_SUCCESS != selector_set_interest_key(key, OP_READ)){
          ret = ERROR;
        }
      }
    }
    return ret;
}

static void * request_resolve(void *data){
    struct selector_key *key = (struct selector_key *) data;
    struct socks5* sock = ATTACHMENT(key);
    // Liberá todos los recursos cuando termines el thread
    pthread_detach(pthread_self());
    sock->origin_resolution = 0;
    struct addrinfo hints = {
        .ai_family    = AF_UNSPEC,
        .ai_socktype  = SOCK_STREAM,
        .ai_flags     = AI_PASSIVE,
        .ai_protocol  = 0,
        .ai_canonname = NULL,
        .ai_addr      = NULL,
        .ai_next      = NULL,
    };
    char buff[7];
    snprintf(buff, sizeof(buff), "%d", sock->origin_port);
    /*
    solveDomain(sock->origin_addr, buff, &hints, &sock->origin_resolution);
    while(sock->origin_resolution != NULL && sock->origin_resolution->ai_family == AF_UNSPEC)
    {
      fprintf(stdout, "Es unspec!\n");
      sock->origin_resolution = sock->origin_resolution->ai_next;
    }
    if(sock->origin_resolution == NULL)
    {
      fprintf(stdout, "Es null\n");
      return 0;
    }
    fprintf(stdout, "Sin Addr: %u\n", ((struct sockaddr_in*)(sock->origin_resolution->ai_addr))->sin_addr.s_addr);
    */
    getaddrinfo(sock->origin_addr, buff, &hints, &sock->origin_resolution);
    selector_notify_block(key->s, key->fd);
    free(data);
    return 0;
}

char* time_stamp()
{
  char *timestamp = (char *)malloc(sizeof(char) * 22);
  time_t ltime;
  ltime=time(NULL);
  struct tm *tm;
  tm=localtime(&ltime);

  sprintf(timestamp,"%04d-%02d-%02dT%02d:%02d:%02dZ", tm->tm_year+1900, tm->tm_mon, tm->tm_mday, tm->tm_hour, tm->tm_min, tm->tm_sec);
  return timestamp;
}

void initialize_communication_parser(struct socks5* sock)
{
  if(sock->origin_fd == 80)
  {
    http_parser_init(&(sock->parser).http);
  }
  else if(sock->origin_fd == 110)
  {
    pop3_parser_init(&(sock->parser).pop3);
  }
}

static unsigned request_process(const struct request_st* d, struct selector_key *key) {
    struct socks5 *sock = ATTACHMENT(key);
    unsigned ret = REQUEST_WRITE;
    uint8_t port[2] = {d->parser.port[0], d->parser.port[1]};
    unsigned short int p = ntohs(*((unsigned short int*)port));
    sock->origin_port = p;
    switch(d->parser.command){
      case req_connect:
        if(d->parser.address_type == ipv4){
            char ip[16];
            snprintf(ip, 16, "%hhu.%hhu.%hhu.%hhu", d->parser.address[0], d->parser.address[1], d->parser.address[2], d->parser.address[3]);
            struct sockaddr_in address;
            memset(&address, 0, sizeof(address));
            address.sin_family = AF_INET;
            sock->origin_fd = socket(AF_INET, SOCK_STREAM, 0);
            sock->origin_port = htons(p);
            address.sin_addr.s_addr = inet_addr(ip);
            address.sin_port = htons(p);
            memcpy(&sock->origin_addr_storage, (struct sockaddr*) &address, INET_ADDRSTRLEN);

            if (connect(sock->origin_fd, (struct sockaddr*) &address, sizeof(address)) == -1){
              if(errno == EINPROGRESS) {
                selector_status st = selector_set_interest(key->s, sock->client_fd, OP_NOOP);
                if(SELECTOR_SUCCESS != st) {
                  return ERROR;
                }
                st = selector_register(key->s, sock->origin_fd, &socks5_handler, OP_WRITE, sock);
                if(SELECTOR_SUCCESS != st) {
                  return ERROR;
                }
              }
            }
            sock->origin_port = ntohs(address.sin_port);
            initialize_communication_parser(sock);
            if(strlen(sock->username) > 0)
              fprintf(stdout, "%s\t%s\tA\t%s\t%d\t%s\t%d\t{estado}\n", time_stamp(), sock->username, inet_ntoa(((struct sockaddr_in *)(&sock->client_addr))->sin_addr), ntohs(((struct sockaddr_in *)(&sock->client_addr))->sin_port), ip, ntohs(address.sin_port));
            else
            {
              fprintf(stdout, "%s\t%s\tA\t%s\t%d\t%s\t%d\t{estado}\n", time_stamp(), "ANON", inet_ntoa(((struct sockaddr_in *)(&sock->client_addr))->sin_addr), ntohs(((struct sockaddr_in *)(&sock->client_addr))->sin_port), ip, ntohs(address.sin_port));
            }
        }
        else if(d->parser.address_type == domain)
        {
          sock->needed_resolve = true;
          ret = REQUEST_RESOLVE;
        }
        else if(d->parser.address_type == ipv6)
        {
          char ip[40];
          snprintf(ip, 40, "%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x",
                            d->parser.address[0], d->parser.address[1], d->parser.address[2], d->parser.address[3], d->parser.address[4], d->parser.address[5], d->parser.address[6], d->parser.address[7],
                            d->parser.address[8], d->parser.address[9], d->parser.address[10], d->parser.address[11], d->parser.address[12], d->parser.address[13], d->parser.address[14], d->parser.address[15]);

          struct sockaddr_in6 address;
          memset(&address, 0, sizeof(address));
          address.sin6_family = AF_INET6;
          sock->origin_fd = socket(AF_INET6, SOCK_STREAM, 0);
          sock->origin_port = htons(p);
          inet_pton(AF_INET6, ip, &address.sin6_addr.s6_addr);
          address.sin6_port = htons(p);
          memcpy(&sock->origin_addr_storage, (struct sockaddr*) &address, INET6_ADDRSTRLEN);

          if (connect(sock->origin_fd, (struct sockaddr*) &address, sizeof(address)) == -1){
            if(errno == EINPROGRESS) {
              selector_status st = selector_set_interest(key->s, sock->client_fd, OP_NOOP);
              if(SELECTOR_SUCCESS != st) {
                return ERROR;
              }
              st = selector_register(key->s, sock->origin_fd, &socks5_handler, OP_WRITE, sock);
              if(SELECTOR_SUCCESS != st) {
                return ERROR;
              }
            }
          }
          sock->origin_port = ntohs(address.sin6_port);
          initialize_communication_parser(sock);
          if(strlen(sock->username) > 0)
            fprintf(stdout, "%s\t%s\tA\t%s\t%d\t%s\t%d\t{estado}\n" ,time_stamp(), sock->username, inet_ntoa(((struct sockaddr_in *)(&sock->client_addr))->sin_addr), ntohs(((struct sockaddr_in *)(&sock->client_addr))->sin_port), ip, ntohs(address.sin6_port));
          else
            fprintf(stdout, "%s\t%s\tA\t%s\t%d\t%s\t%d\t{estado}\n" ,time_stamp(), "ANON", inet_ntoa(((struct sockaddr_in *)(&sock->client_addr))->sin_addr), ntohs(((struct sockaddr_in *)(&sock->client_addr))->sin_port), ip, ntohs(address.sin6_port));
        }
        break;
      case req_bind:
        break;
      case req_udp_associate:
        break;
    }
    return ret;
}

static void request_read_close(const unsigned state, struct selector_key *key){
}

static void request_write_close(const unsigned state, struct selector_key *key){
}

static unsigned request_read(struct selector_key *key) {
    struct request_st *d = &ATTACHMENT(key)->client.request;
    unsigned  ret      = REQUEST_READ;
        bool  error    = false;
     uint8_t *ptr;
      size_t  count;
     ssize_t  n;
    ptr = buffer_write_ptr(d->rb, &count);
    n = recv(key->fd, ptr, count, 0);
    if(n > 0) {
        buffer_write_adv(d->rb, n);
        const enum request_state st = request_consume(d->rb, &d->parser, &error);
        if(request_is_done(st, 0)) {
            if(SELECTOR_SUCCESS == selector_set_interest_key(key, OP_WRITE)) {
                ret = request_process(d, key);
            } else {
                ret = ERROR;
            }
        }
    } else {
        ret = ERROR;
    }
    return error ? ERROR : ret;
}

static void request_resolve_init(const unsigned state, struct selector_key *key){
  struct socks5 *sock = ATTACHMENT(key);
  struct request_st *d = &ATTACHMENT(key)->client.request;
  struct selector_key *dns_key = malloc(sizeof(*dns_key));
  if (dns_key == NULL) {
    selector_unregister_fd(key->s, sock->client_fd);
    abort();
  }
  dns_key->s    = key->s;
  dns_key->fd   = sock->client_fd;
  dns_key->data = sock;

  memcpy(sock->origin_addr, d->parser.address, &(d->parser.addr_ptr)-(d->parser.address));
  pthread_t tid;
  // En otro thread, resolvé el nombre
  if (-1 == pthread_create(&tid, 0, request_resolve, dns_key))
  {
    // no se logro crear el nuevo hilo
    fprintf(stdout, "Error when creating new thread!\n");
    selector_unregister_fd(key->s, sock->client_fd);
    free(dns_key);
    abort();
  }
  sleep(1);
}

static unsigned request_connect(struct selector_key *key, struct socks5* sock)
{
  sock->origin_fd = socket(sock->origin_resolution->ai_family, SOCK_STREAM, 0);
  if (sock->origin_fd == -1) {
    goto finally;
  }
  if (selector_fd_set_nio(sock->origin_fd) == -1) {
    goto finally;
  }
  if (-1 == connect(sock->origin_fd, (const struct sockaddr *) &sock->origin_addr_storage, sock->origin_resolution->ai_addrlen))
  {
    if(errno == EINPROGRESS) {
      selector_status st = selector_set_interest(key->s, sock->client_fd, OP_NOOP);
      if(SELECTOR_SUCCESS != st) {
        goto finally;
      }
      st = selector_register(key->s, sock->origin_fd, &socks5_handler, OP_WRITE, sock);
      if(SELECTOR_SUCCESS != st) {
        goto finally;
      }
      sock->references += 1;
    }
  } else {
    fprintf(stdout, "ERROR!\n");
    abort();
  }
  initialize_communication_parser(sock);
  char* s = NULL;
  if(strlen(sock->username) > 0)
  {
    if(sock->origin_resolution->ai_family == AF_INET)
    {
      s = malloc(INET_ADDRSTRLEN);
      inet_ntop(AF_INET, &((struct sockaddr_in *)((const struct sockaddr *) &sock->origin_addr_storage))->sin_addr, s, INET_ADDRSTRLEN);
      fprintf(stdout, "%s\t%s\tA\t%s\t%d\t%s (%s)\t%d\t{estado}\n", time_stamp(), sock->username, inet_ntoa(((struct sockaddr_in *)(&sock->client_addr))->sin_addr), ntohs(((struct sockaddr_in *)(&sock->client_addr))->sin_port), sock->origin_addr, s, sock->origin_port);
    }
    else if(sock->origin_resolution->ai_family == AF_INET6)
    {
      s = malloc(INET6_ADDRSTRLEN);
      inet_ntop(AF_INET6, &((struct sockaddr_in6 *)((const struct sockaddr *) &sock->origin_addr_storage))->sin6_addr, s, INET6_ADDRSTRLEN);
      fprintf(stdout, "%s\t%s\tA\t%s\t%d\t%s (%s)\t%d\t{estado}\n", time_stamp(), sock->username, inet_ntoa(((struct sockaddr_in *)(&sock->client_addr))->sin_addr), ntohs(((struct sockaddr_in *)(&sock->client_addr))->sin_port), sock->origin_addr, s, sock->origin_port);
    };
  }
  else
  {
    if(sock->origin_resolution->ai_family == AF_INET)
    {
      s = malloc(INET_ADDRSTRLEN);
      inet_ntop(AF_INET, &((struct sockaddr_in *)((const struct sockaddr *) &sock->origin_addr_storage))->sin_addr, s, INET_ADDRSTRLEN);
      fprintf(stdout, "%s\t%s\tA\t%s\t%d\t%s (%s)\t%d\t{estado}\n", time_stamp(), "ANON", inet_ntoa(((struct sockaddr_in *)(&sock->client_addr))->sin_addr), ntohs(((struct sockaddr_in *)(&sock->client_addr))->sin_port), sock->origin_addr, s, sock->origin_port);
    }
      else if(sock->origin_resolution->ai_family == AF_INET6)
    {
      s = malloc(INET6_ADDRSTRLEN);
      inet_ntop(AF_INET6, &((struct sockaddr_in6 *)((const struct sockaddr *) &sock->origin_addr_storage))->sin6_addr, s, INET6_ADDRSTRLEN);
      fprintf(stdout, "%s\t%s\tA\t%s\t%d\t%s (%s)\t%d\t{estado}\n", time_stamp(), "ANON", inet_ntoa(((struct sockaddr_in *)(&sock->client_addr))->sin_addr), ntohs(((struct sockaddr_in *)(&sock->client_addr))->sin_port), sock->origin_addr, s, sock->origin_port);
    }
  }
  return REQUEST_WRITE;

  finally:
    fprintf(stdout, "Error. Couldn't connect %d to their requested origin server\n", sock->client_fd);
    freeaddrinfo(sock->origin_resolution);
    sock->origin_resolution = 0;
    return ERROR;
}

static unsigned request_resolve_done(struct selector_key *key) {
    struct socks5 *sock = ATTACHMENT(key);
    if(sock->origin_resolution == NULL)
    {
      fprintf(stdout, "Unable to connect client %d to requested origin server", sock->client_fd);
      freeaddrinfo(sock->origin_resolution);
      sock->origin_resolution = 0;
      return ERROR;
    }
    else
    {
      memcpy(&sock->origin_addr_storage, sock->origin_resolution->ai_addr, sock->origin_resolution->ai_addrlen);
    }
    return request_connect(key, sock);
}


////////////////////////////////////////////////////////////////////////////////
// COPY
////////////////////////////////////////////////////////////////////////////////
static void copy_init(const unsigned state, struct selector_key *key) {
    struct copy_st *d_cli = &ATTACHMENT(key)->client.copy;
    struct copy_st *d_orig = &ATTACHMENT(key)->orig.copy;
    d_cli->rb                              = &(ATTACHMENT(key)->client_read_buffer);
    d_cli->wb                              = &(ATTACHMENT(key)->client_write_buffer);
    d_orig->rb                              = &(ATTACHMENT(key)->origin_read_buffer);
    d_orig->wb                              = &(ATTACHMENT(key)->origin_write_buffer);
    struct socks5 *sock = ATTACHMENT(key);
    selector_register(key->s, sock->origin_fd, &socks5_handler, OP_READ, sock);
}

static void copy_close(const unsigned state, struct selector_key *key){
}

static unsigned copy_paste_buffer(buffer *from, buffer *to, ssize_t bytes_to_read){

    unsigned ret = COPY;
    size_t n;
    uint8_t aux[bytes_to_read];
    size_t i = 0;

    buffer_write_ptr(to, &n);
    if(n > (size_t) bytes_to_read)
      n = (size_t) bytes_to_read;

    for(i=0; i < n; i++){
      aux[i] = buffer_read(from);
    }

    for(size_t j = 0; j<i; j++) {
      buffer_write(to, aux[j]);
    }
    return ret;
}

void disect_password(struct socks5* sock, buffer* b)
{
  ////////////
  char* s;
  if(sock->needed_resolve)
  {
    s = sock->origin_addr;
  }
  else if(sock->origin_addr_storage.ss_family == AF_INET6){
    s = malloc(INET6_ADDRSTRLEN);
    inet_ntop(AF_INET6, &((struct sockaddr_in6 *)((const struct sockaddr *) &sock->origin_addr_storage))->sin6_addr, s, INET6_ADDRSTRLEN);
  }
  else{
    s = malloc(INET_ADDRSTRLEN);
    inet_ntop(AF_INET, &((struct sockaddr_in *)((const struct sockaddr *) &sock->origin_addr_storage))->sin_addr, s, INET_ADDRSTRLEN);
  }
  ////////////

  if(sock->origin_port == 110 && !pop3_is_done(sock->parser.pop3.state))
  {
    enum pop3_parser_state pop3_st = pop3_consume(b, &(sock->parser).pop3);
    if(pop3_st == pop3_auth_success)
    {
      size_t size = b64_decoded_size(sock->parser.pop3.buffer)+1;
      char* decoded = malloc(size);
      memset(decoded, 0, size);
      b64_decode(sock->parser.pop3.buffer, (uint8_t*) decoded, size);
      for(size_t i=1; i < size; i++)
        if(decoded[i] < 32)
        {
          decoded[i] = '\t';
          break;
        }
      if(strlen(sock->username) > 0)
        fprintf(stdout, "%s\t%s\tP\tPOP3\t%s\t%d\t%s\n", time_stamp(), sock->username, s, sock->origin_port, decoded+1);
      else
        fprintf(stdout, "%s\t%s\tP\tPOP3\t%s\t%d\t%s\n", time_stamp(), "ANON", s, sock->origin_port, decoded+1);
      free(decoded);
    }
    else if(pop3_st == pop3_user_success)
    {
      if(strlen(sock->username) > 0)
        fprintf(stdout, "%s\t%s\tP\tPOP3\t%s\t%d\t%s\n", time_stamp(), sock->username, s, sock->origin_port, sock->parser.pop3.buffer);
      else
        fprintf(stdout, "%s\t%s\tP\tPOP3\t%s\t%d\t%s\n", time_stamp(), "ANON", s, sock->origin_port, sock->parser.pop3.buffer);
    }
  }
  if(sock->origin_port == 80 && !http_is_done(sock->parser.http.state))
  {
    enum http_parser_state http_st = http_consume(b, &(sock->parser).http);
    if(http_st == http_done)
    {
      size_t size = b64_decoded_size(sock->parser.http.base64)+1;
      char* decoded = malloc(size);
      memset(decoded, 0, size);
      b64_decode(sock->parser.http.base64, (uint8_t*) decoded, size);
      for(size_t i=0; i < size; i++)
        if(decoded[i] == ':')
          decoded[i] = '\t';
      if(strlen(sock->username) > 0)
        fprintf(stdout, "%s\t%s\tP\tHTTP\t%s\t%d\t%s\n", time_stamp(), sock->username, s, sock->origin_port, decoded);
      else
        fprintf(stdout, "%s\t%s\tP\tHTTP\t%s\t%d\t%s\n", time_stamp(), "ANON", s, sock->origin_port, decoded);
      free(decoded);
    }
  }
}

static unsigned copy_read(struct selector_key *key) {
      struct copy_st *d_cli = &ATTACHMENT(key)->client.copy;
      struct copy_st *d_orig = &ATTACHMENT(key)->orig.copy;
      struct socks5 *sock = ATTACHMENT(key);
      unsigned ret = COPY;

      uint8_t *ptr;
      size_t  count;
      ssize_t  n;

      if(key->fd == sock->origin_fd){
        ptr = buffer_write_ptr(d_orig->rb, &count);
        n = recv(key->fd, ptr, count, 0);
        if(n <= 0){
          fprintf(stdout, "Connection with origin server %d lost\n", key->fd);
          shutdown(sock->origin_fd, SHUT_RD);
          shutdown(sock->client_fd, SHUT_RD);
          return ERROR;
        }
        buffer_write_adv(d_orig->rb, n);
        selector_status st = selector_set_interest(key->s, sock->origin_fd, OP_NOOP);
        // En rb quedo lo que vamos a leer ahora
        disect_password(sock, d_orig->rb);
        st = selector_set_interest(key->s, sock->client_fd, OP_WRITE);
        if(st != SELECTOR_SUCCESS)
        {
          ret = ERROR;
        }
      }
      else if(key->fd == sock->client_fd){
        ptr = buffer_write_ptr(d_cli->rb, &count);
        n = recv(key->fd, ptr, count, 0);
        if(n <= 0){
          fprintf(stdout, "Connection with client %d lost\n", key->fd);
          shutdown(sock->origin_fd, SHUT_RD);
          shutdown(sock->client_fd, SHUT_RD);
          return ERROR;
        }
        buffer_write_adv(d_cli->rb, n);
        selector_status st = selector_set_interest(key->s, sock->client_fd, OP_NOOP);
        // En rb quedo lo que vamos a leer ahora
        disect_password(sock, d_cli->rb);
        st = selector_set_interest(key->s, sock->origin_fd, OP_WRITE);
        if(st != SELECTOR_SUCCESS)
        {
          ret = ERROR;
        }
      }
      else
      {
        fprintf(stdout, "Unexpected fd: %d\n", key->fd);
        abort();
      }
  return ret;
}

static unsigned copy_write(struct selector_key *key) {
      struct copy_st *d_cli = &ATTACHMENT(key)->client.copy;
      struct copy_st *d_orig = &ATTACHMENT(key)->orig.copy;
      struct socks5 *sock = ATTACHMENT(key);
      unsigned ret = COPY;

      uint8_t *ptr;
      size_t  count;
      size_t  n;

      if(key->fd == sock->origin_fd)
      {
        buffer_read_ptr(d_cli->rb, &n);
        ret = copy_paste_buffer(d_cli->rb, d_orig->wb, n);
        if(ret == COPY)
        {
          // count = cuanto tengo para enviar
          ptr = buffer_read_ptr(d_orig->wb, &count);
          if(send(sock->origin_fd, ptr, count, MSG_DONTWAIT) < 0)
            ret = ERROR;
          else
          {
            buffer_read_adv(d_orig->wb, count);
            fprintf(stdout, "Sent %d -> %d\n", sock->client_fd, sock->origin_fd);
            transferred_bytes += count;
            buffer_compact(d_orig->wb);
          }
        }
      }
      else if(key->fd == sock->client_fd)
      {
        buffer_read_ptr(d_orig->rb, &n);
        ret = copy_paste_buffer(d_orig->rb, d_cli->wb, n);
        if(ret == COPY)
        {
          ptr = buffer_read_ptr(d_cli->wb, &count);
          if(send(sock->client_fd, ptr, count, MSG_DONTWAIT) < 0)
            ret = ERROR;
          else
          {
            buffer_read_adv(d_cli->wb, count);
            fprintf(stdout, "Sent %d <- %d\n", sock->client_fd, sock->origin_fd);
            transferred_bytes += count;
            buffer_compact(d_cli->wb);
          }
        }
      }
      selector_status st = selector_set_interest(key->s, sock->origin_fd, OP_READ);
      st = selector_set_interest(key->s, sock->client_fd, OP_READ);
      if(st != SELECTOR_SUCCESS)
      {
        ret = ERROR;
      }
      return ret;
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
      .on_arrival       = hello_write_init,
      .on_departure     = hello_write_close,
      .on_write_ready   = hello_write,
    },
    {
      .state            = AUTH_READ,
      .on_arrival       = auth_read_init,
      .on_read_ready    = auth_read,
    },
    {
      .state            = AUTH_WRITE,
      .on_write_ready   = auth_write,
    },
    {
      .state            = REQUEST_READ,
      .on_arrival       = request_read_init,
      .on_departure     = request_read_close,
      .on_read_ready    = request_read,
    },
    {
      .state            = REQUEST_RESOLVE,
      .on_arrival       = request_resolve_init,
      .on_block_ready   = request_resolve_done,
    },
    {
      .state            = REQUEST_WRITE,
      .on_arrival       = request_write_init,
      .on_departure     = request_write_close,
      .on_write_ready   = request_write,
    },
    {
      .state            = COPY,
      .on_arrival       = copy_init,
      .on_departure     = copy_close,
      .on_read_ready    = copy_read,
      .on_write_ready   = copy_write,
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
    //fprintf(stdout, "Closing connection between file descriptors %d-%d\n", ATTACHMENT(key)->client_fd, ATTACHMENT(key)->origin_fd);
    const int fds[] = {
        ATTACHMENT(key)->client_fd,
        ATTACHMENT(key)->origin_fd,
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
    active_connections--;
}
