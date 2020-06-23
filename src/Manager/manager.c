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
#include <netinet/sctp.h>
#include <netdb.h>
#include "hello_manager.h"
#include "request_manager.h"
#include "args_manager.h"
#include "manager.h"
#include "../Proxy/buffer.h"
#include "../Proxy/netutils.h"

#define N(x) (sizeof(x)/sizeof((x)[0]))
#define MAX_BUFFER_SIZE 4096

#define SUCCESS 1
#define ERROR -1

  struct manager* manager;
unsigned int buffer_size;
struct manager_args* args;
static bool done = false;

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
    } state;

  int socks_fd;

  uint8_t raw_buff_a[2048];
  uint8_t raw_buff_b[2048];
  buffer manager_read_buffer;
  buffer manager_write_buffer;
}manager_st;


/////////////////////////////////////////////////////////
//HELLO
/////////////////////////////////////////////////////////

static int hello_manager_write(struct manager* manager) {
  struct hello_manager_st *d = &(manager->state.hello);
  d->rb = &(manager->manager_read_buffer);
  d->wb = &(manager->manager_write_buffer);

  int ret = SUCCESS;

  hello_manager_marshall(d->wb, (uint8_t*) args->auth.name, strlen(args->auth.name), (uint8_t*) args->auth.pass, strlen(args->auth.pass));

  size_t  count;
  uint8_t *ptr = buffer_read_ptr(d->wb, &count);

  if(count < 5) {
      return ERROR;
  }

  size_t n = send(manager->socks_fd, ptr, count, MSG_DONTWAIT);

  if(n < 5) {
    ret = ERROR;
  }

  buffer_read_adv(d->wb, n);

  return ret;
}

static int hello_manager_read(struct manager* manager) {
  struct hello_manager_st *d = &(manager->state.hello);
  d->rb = &(manager->manager_read_buffer);
  d->wb = &(manager->manager_write_buffer);
  hello_manager_parser_init(&d->parser);

  int ret = SUCCESS;
  bool  error = false;
  uint8_t *ptr;
  size_t  count;
  ssize_t  n;

  ptr = buffer_write_ptr(d->rb, &count);
  n = recv(manager->socks_fd, ptr, count, 0);

    if(n > 0) {
        buffer_write_adv(d->rb, n);

        const enum hello_manager_state st = hello_manager_consume(d->rb, &d->parser, &error);

        if(error) {
          fprintf(stdout, "Acceso denegado: no autorizado\n");
        }

        if(!hello_manager_is_done(st, 0)) {
          ret = ERROR;
        }
    }

    else {
        ret = ERROR;
    }

    return error ? ERROR : ret;
}

/////////////////////////////////////////////////////////
//REQUEST
/////////////////////////////////////////////////////////

static void unsigned_to_byte_converter(unsigned long number, uint8_t aux[], int size) {
  aux[0] = (uint8_t) number;
  for(int i = 1; i < size; i++) {
    aux[i] = (uint8_t) (number >> i*8);
  }
  return;
}

static int request_manager_write(struct manager* manager) {
  struct request_manager_st *d = &(manager->state.request);
  d->rb = &(manager->manager_read_buffer);
  d->wb = &(manager->manager_write_buffer);
  int ret = SUCCESS;
  size_t  count;
    if(args->command == 0x00) {
      request_marshall_new_user(d->wb, (uint8_t*) args->params.new_user.name, strlen(args->params.new_user.name),
        (uint8_t*) args->params.new_user.pass, strlen(args->params.new_user.pass));
    }

    else if(args->command == 0x01 || args->command == 0x02) {
      request_marshall_get_info(d->wb, args->command);
    }

    else if(args->command == 0x03) {
      uint8_t new_max_amount[4];
      unsigned_to_byte_converter(args->params.new_clients_size, new_max_amount, 4);
      request_marshall_change_clients(d->wb, new_max_amount);
    }

    else {
      fprintf(stdout, "Comando inválido");
      return ERROR;
    }

    uint8_t *ptr = buffer_read_ptr(d->wb, &count);
    if(count < 2) {
      return ERROR;
    }

    size_t n = send(manager->socks_fd, ptr, count, MSG_DONTWAIT);
    if(n < 2) {
      ret = ERROR;
    }

    buffer_read_adv(d->wb, n);

    return ret;
}

static void request_manager_process(struct request_manager_st* d, bool error) {
  if(args->command == 0x00) {
    if(error) {
      fprintf(stdout, "No se pudo crear el usuario. Es posible que se haya superado el máximo de usuarios permitidos.\n");
    }
    else {
      fprintf(stdout, "Nuevo usuario agregado: %s\n", args->params.new_user.name);
    }
  }
  else if(args->command == 0x01) {
    fprintf(stdout, "Usuarios actuales:\n");
    for(int i = 0; i < d->parser.user_number; i++) {
      fprintf(stdout, "%s\n", (char*) d->parser.users[i]);
    }
  }

  else if(args->command == 0x02) {
    fprintf(stdout, "Conexiones históricas:   %ld\n"
    "Conexiones concurrentes:   %d\n"
    "Bytes transferidos:    %ld\n", *((unsigned long*)(void*) d->parser.total_con), *((unsigned int*)(void*) d->parser.active_con),
     *((unsigned long*)(void*) d->parser.bytes));
  }

  else if(args->command == 0x03) {
    if(error) {
      fprintf(stdout, "No pudieron realizarse los cambios solicitados\n");
    }
    else {
      fprintf(stdout, "Nueva cantidad máxima de clientes simultáneos: %d\n", args->params.new_clients_size);
    }
  }
}

static int request_manager_read(struct manager* manager) {
  struct request_manager_st *d = &(manager->state.request);
  d->rb = &(manager->manager_read_buffer);
  d->wb = &(manager->manager_write_buffer);
  request_manager_parser_init(&d->parser);
  int ret = SUCCESS;

  bool  error = false;
  uint8_t *ptr;
  size_t  count;
  ssize_t  n;

  ptr = buffer_write_ptr(d->rb, &count);

  n = recv(manager->socks_fd, ptr, count, 0);

  if(n > 0) {
    buffer_write_adv(d->rb, n);

    const enum request_manager_state st = request_manager_consume(d->rb, &d->parser, &error);

    if(request_manager_is_done(st, 0)) {
      request_manager_process(d, error);
    }
    else {
      ret = ERROR;
    }

  }
  else {
    ret = ERROR;
  }

  return error ? ERROR : ret;
}


/////////////////////////////////////////////////////////
//MAIN
/////////////////////////////////////////////////////////

static void close_manager(int sock) {
    free(args);
    free(manager);
    close(sock);
}

static void start_manager(int sock) {
  manager = malloc(sizeof(*manager));
  manager->socks_fd = sock;
  buffer_init(&manager->manager_read_buffer, N(manager->raw_buff_a), manager->raw_buff_a);
  buffer_init(&manager->manager_write_buffer, N(manager->raw_buff_b), manager->raw_buff_b);

  fd_set socketSet;
  FD_ZERO(&socketSet);
  FD_SET(sock, &socketSet);

  sigset_t blockset;
  sigemptyset(&blockset);
  sigaddset(&blockset, SIGINT);
  sigaddset(&blockset, SIGPIPE);
  sigprocmask(SIG_BLOCK, &blockset, NULL);

  pselect(sock+1, NULL, &socketSet, NULL, NULL, &blockset);

  if(hello_manager_write(manager) != SUCCESS) {
    fprintf(stdout, "Error: Cerrando conexión\n");
    return;
  }

  pselect(sock+1, &socketSet, NULL, NULL, NULL, &blockset);

  if(hello_manager_read(manager) != SUCCESS) {
    fprintf(stdout, "Error: Cerrando conexión\n");
    return;
  }

  pselect(sock+1, NULL, &socketSet, NULL, NULL, &blockset);

  if(request_manager_write(manager) != SUCCESS) {
    fprintf(stdout, "Error: Cerrando conexión\n");
    return;
  }

  pselect(sock+1, &socketSet, NULL, NULL, NULL, &blockset);

  if(request_manager_read(manager) != SUCCESS) {
    fprintf(stdout, "Error: Cerrando conexión\n");
    return;
  }

  return;
}


int main(const int argc, char **argv) {
    buffer_size = 2046;

    int sock;

    args = malloc(sizeof(struct manager_args));
    parse_manager_args(argc, argv, args);

    close(0);

    if(strchr(args->socks_addr, ':') == NULL) {
        struct sockaddr_in addr;
        memset(&addr, 0, sizeof(addr));
        addr.sin_family = AF_INET;
        addr.sin_addr.s_addr = inet_addr(args->socks_addr);
        addr.sin_port = htons(args->socks_port);
        sock = socket(AF_INET, SOCK_STREAM, IPPROTO_SCTP);
        if(connect(sock, (struct sockaddr*) &addr, sizeof(addr)) == -1) {
          fprintf(stderr, "No pudo conectarse al proxy.\n");
          return 1;
      }
    }
    else {
        struct sockaddr_in6 addr;
        memset(&addr, 0, sizeof(addr));
        addr.sin6_family = AF_INET6;
        inet_pton(AF_INET6, args->socks_addr, &addr.sin6_addr.s6_addr);
        addr.sin6_port = htons(args->socks_port);
        sock = socket(AF_INET6, SOCK_STREAM, IPPROTO_SCTP);
        if(connect(sock, (struct sockaddr*) &addr, sizeof(addr)) == -1) {
          fprintf(stderr, "No pudo conectarse al proxy\n");
          return 1;
      }

    }
    start_manager(sock);
    close_manager(sock);
}
