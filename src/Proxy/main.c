#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <limits.h>
#include <errno.h>
#include <signal.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <netinet/sctp.h>
#include <arpa/inet.h>
#include "socks5.h"
#include "manager_server.h"
#include "selector.h"
#include "args.h"
#include "logger.h"

#define MAX_CONNECTIONS 1024

#define DEFAULT_SELECTOR_TIMEOUT 10

unsigned long total_connections;
unsigned int active_connections;
unsigned long transferred_bytes;
unsigned int max_clients;
bool disectors_enabled;
unsigned int buffer_size;
struct doh* doh;

static bool done = false;

static void sigterm_handler(const int signal) {
    done = true;
}

char* registered_users[MAX_USERS][2];

void register_users(struct users* users, char* registered_users[MAX_USERS][2])
{
  for(int i=0; i < MAX_USERS; i++)
  {
    if(users[i].name != NULL && users[i].pass != NULL)
    {
      registered_users[i][0] = malloc(256*sizeof(char));
      memset(registered_users[i][0], 0, 256);
      memcpy(registered_users[i][0], users[i].name, strlen(users[i].name));
      registered_users[i][1] = malloc(256*sizeof(char));
      memset(registered_users[i][1], 0, 256);
      memcpy(registered_users[i][1], users[i].pass, strlen(users[i].pass));
    }
  }
}

void destroy_users(char* registered_users[MAX_USERS][2])
{
  for(int i=0; i < MAX_USERS; i++)
  {
    if(registered_users[i][0] != NULL && registered_users[i][1] != NULL)
    {
      free(registered_users[i][0]);
      free(registered_users[i][1]);
    }
  }
}

int create_ipv4_socket(struct socks5args* args)
{
  struct sockaddr_in addr;
  memset(&addr, 0, sizeof(addr));
  addr.sin_family = AF_INET;
  addr.sin_addr.s_addr = inet_addr(args->socks_addr);
  addr.sin_port = htons(args->socks_port);

  int server = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
  if(server < 0) {
      return -1;
  }
  log(DEBUG, "Esperando clientes en %s:%d (TCP)", args->socks_addr, args->socks_port);
  setsockopt(server, SOL_SOCKET, SO_REUSEADDR, &(int){ 1 }, sizeof(int));
  if(bind(server, (struct sockaddr*) &addr, sizeof(addr)) < 0) {
      return -2;
  }
  if (listen(server, 20) < 0) {
      return -3;
  }
  return server;
}

int create_ipv6_socket(struct socks5args* args)
{
  struct sockaddr_in6 addr;
  memset(&addr, 0, sizeof(addr));
  addr.sin6_family = AF_INET6;

  if(strcmp(args->socks_addr, "0.0.0.0") != 0)
  {
    inet_pton(AF_INET6, args->socks_addr, &addr.sin6_addr.s6_addr);
    log(DEBUG, "Esperando clientes en [%s]:%d (TCP)", args->socks_addr, args->socks_port);
  }
  else
  {
    inet_pton(AF_INET6, "::", &addr.sin6_addr.s6_addr);
    log(DEBUG, "Esperando clientes en [%s]:%d (TCP)", "::", args->socks_port);
  }
  addr.sin6_port = htons(args->socks_port);

  int server = socket(AF_INET6, SOCK_STREAM, IPPROTO_TCP);
  if(server < 0) {
      return -1;
  }
  setsockopt(server, SOL_SOCKET, SO_REUSEADDR, &(int){ 1 }, sizeof(int));
  setsockopt(server, IPPROTO_IPV6, IPV6_V6ONLY, &(int){ 1 }, sizeof(int));
  if(bind(server, (struct sockaddr*) &addr, sizeof(addr)) < 0) {
      return -2;
  }
  if (listen(server, 20) < 0) {
      return -3;
  }
  return server;
}

static int create_ipv4_manager_socket(struct socks5args* args) {

  struct sockaddr_in addr;
  memset(&addr, 0, sizeof(addr));

  struct sctp_initmsg initmsg;

  addr.sin_family = AF_INET;
  addr.sin_addr.s_addr = inet_addr(args->mng_addr);
  addr.sin_port = htons(args->mng_port);

  int mng_fd = socket(AF_INET, SOCK_STREAM, IPPROTO_SCTP);

  if(mng_fd < 0) {
    return -1;
  }

  memset (&initmsg, 0, sizeof (initmsg));
  initmsg.sinit_num_ostreams = 5;
  initmsg.sinit_max_instreams = 5;
  initmsg.sinit_max_attempts = 4;

  if(setsockopt(mng_fd, IPPROTO_SCTP, SCTP_INITMSG, &initmsg, sizeof(initmsg))){
    return -1;
  }

  setsockopt(mng_fd, SOL_SOCKET, SO_REUSEADDR, &(int){ 1 }, sizeof(int));

  if(bind(mng_fd, (struct sockaddr*) &addr, sizeof(addr)) < 0) {
    return -2;
  }

  if (listen(mng_fd, 5) < 0) {
    return -3;
  }

  log(DEBUG, "Esperando administradores en %s:%d (TCP)", args->mng_addr, args->mng_port);
  return mng_fd;
}

static int create_ipv6_manager_socket(struct socks5args* args) {

  struct sockaddr_in6 addr;
  memset(&addr, 0, sizeof(addr));

  struct sctp_initmsg initmsg;

  addr.sin6_family = AF_INET6;

  if(strcmp(args->mng_addr, "0.0.0.0") != 0)
  {
    inet_pton(AF_INET6, args->mng_addr, &addr.sin6_addr.s6_addr);
    log(DEBUG, "Esperando administradores en [%s]:%d (TCP)", args->mng_addr, args->mng_port);
  }
  else
  {
    inet_pton(AF_INET6, "::", &addr.sin6_addr.s6_addr);
    log(DEBUG, "Esperando administradores en [%s]:%d (TCP)", "::", args->mng_port);
  }
  addr.sin6_port = htons(args->mng_port);

  int mng_fd = socket(AF_INET6, SOCK_STREAM, IPPROTO_SCTP);

  if(mng_fd < 0) {
    return -1;
  }

  memset (&initmsg, 0, sizeof (initmsg));
  initmsg.sinit_num_ostreams = 5;
  initmsg.sinit_max_instreams = 5;
  initmsg.sinit_max_attempts = 4;

  if(setsockopt(mng_fd, IPPROTO_SCTP, SCTP_INITMSG, &initmsg, sizeof(initmsg))){
    return -1;
  }

  setsockopt(mng_fd, SOL_SOCKET, SO_REUSEADDR, &(int){ 1 }, sizeof(int));
  setsockopt(mng_fd, IPPROTO_IPV6, IPV6_V6ONLY, &(int){ 1 }, sizeof(int));

  if(bind(mng_fd, (struct sockaddr*) &addr, sizeof(addr)) < 0) {
    return -2;
  }

  if (listen(mng_fd, 5) < 0) {
    return -3;
  }

  return mng_fd;
}


int main(const int argc, char **argv) {
    // Change to DEBUG to see all logs
    setLogLevel(INFO);
    total_connections = 0;
    active_connections = 0;
    transferred_bytes = 0;
    max_clients = MAX_CLIENTS;
    buffer_size = 2046;

    struct socks5args* args = malloc(sizeof(struct socks5args));
    parse_args(argc, argv, args);

    register_users(args->users, registered_users);
    disectors_enabled = args->disectors_enabled;
    doh = &(args->doh);

    // no tenemos nada que leer de stdin
    close(0);

    const char* err_msg = NULL;
    selector_status ss = SELECTOR_SUCCESS;
    fd_selector selector = NULL;

    int server;
    int server2 = -4;

    if(strcmp(args->socks_addr, "0.0.0.0") == 0)
    {
      server = create_ipv6_socket(args);
      if(server == -1)
      {
        err_msg = "unable to create socket";
        goto finally;
      }
      else if(server == -2)
      {
        err_msg = "unable to bind socket";
        goto finally;
      }
      else if(server == -3)
      {
        err_msg = "unable to listen";
        goto finally;
      }

      server2 = create_ipv4_socket(args);
      if(server2 == -1)
      {
        err_msg = "unable to create socket";
        goto finally;
      }
      else if(server2 == -2)
      {
        err_msg = "unable to bind socket";
        goto finally;
      }
      else if(server2 == -3)
      {
        err_msg = "unable to listen";
        goto finally;
      }

    }
    else
    {
      if(strchr(args->socks_addr, ':') != NULL)
      {
        server = create_ipv6_socket(args);
        if(server == -1)
        {
          err_msg = "unable to create socket";
          goto finally;
        }
        else if(server == -2)
        {
          err_msg = "unable to bind socket";
          goto finally;
        }
        else if(server == -3)
        {
          err_msg = "unable to listen";
          goto finally;
        }
      }
      else
      {
        server = create_ipv4_socket(args);
        if(server == -1)
        {
          err_msg = "unable to create socket";
          goto finally;
        }
        else if(server == -2)
        {
          err_msg = "unable to bind socket";
          goto finally;
        }
        else if(server == -3)
        {
          err_msg = "unable to listen";
          goto finally;
        }
      }
    }

    int manager;
    int manager2 = -4;
    if(strcmp(args->mng_addr, "0.0.0.0") == 0)
    {
      manager = create_ipv6_manager_socket(args);
      if(manager == -1)
      {
        err_msg = "unable to create socket";
        goto finally;
      }
      else if(manager == -2)
      {
        err_msg = "unable to bind socket";
        goto finally;
      }
      else if(manager == -3)
      {
        err_msg = "unable to listen";
        goto finally;
      }

      manager2 = create_ipv4_manager_socket(args);
      if(manager2 == -1)
      {
        err_msg = "unable to create socket";
        goto finally;
      }
      else if(manager2 == -2)
      {
        err_msg = "unable to bind socket";
        goto finally;
      }
      else if(manager2 == -3)
      {
        err_msg = "unable to listen";
        goto finally;
      }
    }
    else
    {
      if(strchr(args->mng_addr, ':') != NULL)
      {
        manager = create_ipv6_manager_socket(args);
        if(manager == -1)
        {
          err_msg = "unable to create socket";
          goto finally;
        }
        else if(manager == -2)
        {
          err_msg = "unable to bind socket";
          goto finally;
        }
        else if(manager == -3)
        {
          err_msg = "unable to listen";
          goto finally;
        }
      }
      else
      {
        manager = create_ipv4_manager_socket(args);
        if(manager == -1)
        {
          err_msg = "unable to create socket";
          goto finally;
        }
        else if(manager == -2)
        {
          err_msg = "unable to bind socket";
          goto finally;
        }
        else if(manager == -3)
        {
          err_msg = "unable to listen";
          goto finally;
        }
      }
    }

    // registrar sigterm es ??til para terminar el programa normalmente.
    // esto ayuda mucho en herramientas como valgrind.
    signal(SIGTERM, sigterm_handler);
    signal(SIGINT,  sigterm_handler);
    signal(SIGPIPE, SIG_IGN);

    if(selector_fd_set_nio(server) == -1) {
        err_msg = "getting server socket flags";
        goto finally;
    }
    if(server2 > 0 && selector_fd_set_nio(server2) == -1)
    {
      err_msg = "getting server socket flags";
      goto finally;
    }
    if(selector_fd_set_nio(manager) == -1) {
        err_msg = "getting server socket flags";
        goto finally;
    }

    const struct selector_init conf = {
        .signal = SIGALRM,
        .select_timeout = {
            .tv_sec  = DEFAULT_SELECTOR_TIMEOUT,
            .tv_nsec = 0,
        },
    };
    if(0 != selector_init(&conf)) {
        err_msg = "initializing selector";
        goto finally;
    }

    selector = selector_new(MAX_CONNECTIONS);
    if(selector == NULL) {
        err_msg = "unable to create selector";
        goto finally;
    }

    const struct fd_handler socksv5 = {
        .handle_read       = socksv5_passive_accept,
        .handle_write      = NULL,
        .handle_close      = NULL, // nada que liberar
    };

    const struct fd_handler manager_handler = {
        .handle_read       = manager_server_start,
        .handle_write      = NULL,
        .handle_close      = NULL,
    };

    ss = selector_register(selector, server, &socksv5, OP_READ, NULL);
    if(ss != SELECTOR_SUCCESS) {
        err_msg = "registering fd";
        goto finally;
    }

    if(server2 > 0)
      ss = selector_register(selector, server2, &socksv5, OP_READ, NULL);
    if(ss != SELECTOR_SUCCESS) {
        err_msg = "registering fd";
        goto finally;
    }

    ss = selector_register(selector, manager, &manager_handler, OP_READ, NULL);
    if(ss != SELECTOR_SUCCESS) {
        err_msg = "registering fd";
        goto finally;
    }

    if(manager2 > 0)
      ss = selector_register(selector, manager2, &manager_handler, OP_READ, NULL);
    if(ss != SELECTOR_SUCCESS) {
        err_msg = "registering fd";
        goto finally;
    }

    // CICLO DEL PROGRAMA
    for(;!done;) {
        err_msg = NULL;
        ss = selector_select(selector);
        if(ss != SELECTOR_SUCCESS) {
            err_msg = "serving";
            goto finally;
        }
    }
    free(args);
    destroy_users(registered_users);
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
    socksv5_pool_destroy();

    if(server >= 0) {
        close(server);
    }
    if(server2 >= 0) {
        close(server2);
    }
    if(manager >= 0) {
        close(server2);
    }
    return ret;
}
