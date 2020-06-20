/**
 * main.c - servidor proxy socks concurrente
 *
 * Interpreta los argumentos de línea de comandos, y monta un socket
 * pasivo.
 *
 * Todas las conexiones entrantes se manejarán en éste hilo.
 *
 * Se descargará en otro hilos las operaciones bloqueantes (resolución de
 * DNS utilizando getaddrinfo), pero toda esa complejidad está oculta en
 * el selector.
 */
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
#include <arpa/inet.h>
#include "socks5.h"
#include "selector.h"
#include "args.h"

#define MAX_CONNECTIONS 1024  // should be larger than max_clients*2
#define MAX_CLIENTS 500

unsigned long total_connections;
unsigned int active_connections;
unsigned long transferred_bytes;
unsigned int max_clients;
bool disectors_enabled;
unsigned int buffer_size;

static bool done = false;

static void sigterm_handler(const int signal) {
    printf("signal %d, cleaning up and exiting\n",signal);
    done = true;
}

void register_users(struct users* users)
{
  FILE* f = fopen("users.txt", "w");
  for(int i=0; i < MAX_USERS; i++)
  {
    if(users[i].name != NULL && users[i].pass != NULL)
    {
      fprintf(f, "%s:%s\n", users[i].name, users[i].pass);
    }
  }
  fclose(f);
}

int main(const int argc, char **argv) {
    total_connections = 0;
    active_connections = 0;
    transferred_bytes = 0;
    max_clients = MAX_CLIENTS;
    buffer_size = 2046;

    struct socks5args* args = malloc(sizeof(struct socks5args));
    parse_args(argc, argv, args);
    fprintf(stdout, "El manager está en %s:%d\n", args->mng_addr, args->mng_port);
    fprintf(stdout, "El DoH está en %s:%d y es el host %s\n", args->doh.ip, args->doh.port, args->doh.host);
    register_users(args->users);
    disectors_enabled = args->disectors_enabled;

    // no tenemos nada que leer de stdin
    close(0);

    const char* err_msg = NULL;
    selector_status ss = SELECTOR_SUCCESS;
    fd_selector selector = NULL;

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = inet_addr(args->socks_addr);
    addr.sin_port = htons(args->socks_port);

    // CREAMOS EL SOCKET PASIVO
    const int server = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if(server < 0) {
        err_msg = "unable to create socket";
        goto finally;
    }
    fprintf(stdout, "Listening on TCP port %d\n", args->socks_port);

    // man 7 ip. no importa reportar nada si falla.
    setsockopt(server, SOL_SOCKET, SO_REUSEADDR, &(int){ 1 }, sizeof(int));

    if(bind(server, (struct sockaddr*) &addr, sizeof(addr)) < 0) {
        err_msg = "unable to bind socket";
        goto finally;
    }

    if (listen(server, 20) < 0) {
        err_msg = "unable to listen";
        goto finally;
    }

    // registrar sigterm es útil para terminar el programa normalmente.
    // esto ayuda mucho en herramientas como valgrind.
    signal(SIGTERM, sigterm_handler);
    signal(SIGINT,  sigterm_handler);
    signal(SIGPIPE, SIG_IGN);

    if(selector_fd_set_nio(server) == -1) {
        err_msg = "getting server socket flags";
        goto finally;
    }
    const struct selector_init conf = {
        .signal = SIGALRM,
        .select_timeout = {
            .tv_sec  = 10,
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
    ss = selector_register(selector, server, &socksv5, OP_READ, NULL);
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
    return ret;
}
