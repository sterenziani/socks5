#include <stdio.h>     /* for printf */
#include <stdlib.h>    /* for exit */
#include <limits.h>    /* LONG_MIN et al */
#include <string.h>    /* memset */
#include <errno.h>
#include <getopt.h>
#include <stdbool.h>

#include "args_manager.h"

static unsigned short
port(const char *s) {
     char *end     = 0;
     const long sl = strtol(s, &end, 10);

     if (end == s|| '\0' != *end
        || ((LONG_MIN == sl || LONG_MAX == sl) && ERANGE == errno)
        || sl < 0 || sl > USHRT_MAX) {
         fprintf(stderr, "El puerto debe estar en el rango 1-65536: %s\n", s);
         exit(1);
         return 1;
     }
     return (unsigned short)sl;
}

static void
user(char *s, struct users *user) {
    char *p = strchr(s, ':');
    if(p == NULL) {
        fprintf(stderr, "Contraseña no encontrada\n");
        exit(1);
    } else {
        *p = 0;
        p++;
        user->name = s;
        user->pass = p;
    }

}

static void
version(void) {
  fprintf(stderr, "ManagerSocksv5 version 1.0\n"
                  "ITBA Protocolos de Comunicación 2020/1 -- Grupo 2\n"
}

static void
usage(const char *progname) {
    fprintf(stderr,
        "Uso: %s [OPCIÓN]...\n"
        "\n"
        "   -h               Imprime la ayuda y termina.\n"
        "   -l <SOCKS addr>  Dirección donde servirá el proxy SOCKS.\n"
        "   -p <SOCKS port>  Puerto entrante conexiones SOCKS.\n"
        "   -u <name>:<pass> Usuario y contraseña de usuario que quiere usar el manager.\n"
        "   -a <name>:<pass> Agregar un usuario y contraseña.\n"
        "   -m               Obtener métricas sobre el funcionamiento del servidor.\n"
        "   -U               Listar usuarios del proxy.\n"
        "   -s <new size>    Cambiar cantidad máxima de clientes concurrentes. Máximo 505 clientes.\n"
        "   -v               Imprime información sobre la versión y termina.\n"
        ,
        progname);
    exit(1);
}

void
parse_manager_args(const int argc, char **argv, struct manager_args *args) {
    memset(args, 0, sizeof(*args)); // sobre todo para setear en null los punteros de users

    bool auth = false;

    bool flag = false;

    args->socks_addr = "127.0.0.1";
    args->socks_port = 8080;
    args->command = 0xFF;

    int c;
    int nusers = 0;

    while (true) {

        c = getopt(argc, argv, "hl:p:u:a:mUs:v");
        if (c == -1)
            break;

        switch (c) {
            case 'h':
                usage(argv[0]);
                break;
            case 'l':
                args->socks_addr = optarg;
                break;
            case 'p':
                args->socks_port = port(optarg);
                break;
            case 'u':
                user(optarg, &(args->auth));
                auth = true;
                break;
            case 'a':
                if(args->command != 0xFF) {
                    fprintf(stderr, "Solo se permite un comando a la vez (Flags de comando: -a -m -s -U)\n"
                        "Use el flag -h para mas información\n");
                    exit(1);
                }
                user(optarg, &(args->params.new_user));
                args->command = 0x00;
                flag = true;
                break;
            case 'm':
                if(args->command != 0xFF) {
                    fprintf(stderr, "Solo se permite un comando a la vez (Flags de comando: -a -m -s -U)\n"
                        "Use el flag -h para mas información\n");
                    exit(1);
                }
                args->command = 0x02;
                flag = true;
                break;
            case 'U':
                if(args->command != 0xFF) {
                    fprintf(stderr, "Solo se permite un comando a la vez (Flags de comando: -a -m -s -U)\n"
                        "Use el flag -h para mas información\n");
                    exit(1);
                }
                args->command = 0x01;
                flag = true;
                break;
                case 's':
                if(args->command != 0xFF) {
                    fprintf(stderr, "Solo se permite un comando a la vez (Flags de comando: -a -m -s -U)\n"
                        "Use el flag -h para mas información\n");
                    exit(1);
                }
                args->command = 0x03;
                if(atoi(optarg) > 505) {
                    fprintf(stderr, "Tamaño máximo de clientes es 505\n");
                    exit(1);
                }
                args->params.new_clients_size = atoi(optarg);
                flag = true;
                break;
            case 'v':
                version();
                exit(0);
                break;
            default:
                fprintf(stderr, "Argumento desconocido %d.\n", c);
                exit(1);
        }

    }
    if (optind < argc) {
        fprintf(stderr, "Argumento no aceptadp: ");
        while (optind < argc) {
            fprintf(stderr, "%s ", argv[optind++]);
        }
        fprintf(stderr, "\n");
        exit(1);
    }

    else if(!flag) {
        fprintf(stderr, "Se necesita un comando para iniciar el manager\n Use el flag -h para mas informacion\n");
        exit(1);
    }

    else if(!auth) {
        fprintf(stderr, "Se necesita identificar como usuario para iniciar el manager\n Use el flag -h para mas informacion\n");
        exit(1);
    }
}
