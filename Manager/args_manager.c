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
         fprintf(stderr, "port should in in the range of 1-65536: %s\n", s);
         exit(1);
         return 1;
     }
     return (unsigned short)sl;
}

static void
user(char *s, struct users *user) {
    char *p = strchr(s, ':');
    if(p == NULL) {
        fprintf(stderr, "password not found\n");
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
    fprintf(stderr, "socksv5 version 1.0\n"
                    "ITBA Protocolos de Comunicación 2020/1 -- Grupo 2\n"
                    "AQUI VA LA LICENCIA\n");
}

static void
usage(const char *progname) {
    fprintf(stderr,
        "Usage: %s [OPTION]...\n"
        "\n"
        "   -h               Imprime la ayuda y termina.\n"
        "   -l <SOCKS addr>  Dirección donde servirá el proxy SOCKS.\n"
        "   -p <SOCKS port>  Puerto entrante conexiones SOCKS.\n"
        "   -u <name>:<pass> Usuario y contraseña de usuario que quiere usar el manager.\n"
        "   -a <name>:<pass> Agregar un usuario y contraseña.\n"
        "   -m               Obtener métricas sobre el funcionamiento del servidor.\n"
        "   -U               Listar usuarios del proxy.\n"
        "   -s <new size>    Cambiar tamaño de pool.\n"
        "   -v               Imprime información sobre la versión y termina.\n"
        ,
        progname);
    exit(1);
}

void
parse_manager_args(const int argc, char **argv, struct manager_args *args) {
    memset(args, 0, sizeof(*args)); // sobre todo para setear en null los punteros de users

    args->socks_addr = "0.0.0.0";
    args->socks_port = 1080;
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
                break;           
            case 'a':
                if(args->command != 0xFF) {
                    fprintf(stderr, "Solo se permite un comando a la vez (Flags de comando: -a -m -s -U)\n"
                        "Use el flag -h para mas información\n");
                    exit(1);
                }
                user(optarg, &(args->params.new_user));
                args->command = 0x00;  
                break;
            case 'm':
                if(args->command != 0xFF) {
                    fprintf(stderr, "Solo se permite un comando a la vez (Flags de comando: -a -m -s -U)\n"
                        "Use el flag -h para mas información\n");
                    exit(1);
                }
                args->command = 0x02;
                break;
            case 'U':
                if(args->command != 0xFF) {
                    fprintf(stderr, "Solo se permite un comando a la vez (Flags de comando: -a -m -s -U)\n"
                        "Use el flag -h para mas información\n");
                    exit(1);
                }
                args->command = 0x01;
                break;
                case 's':
                if(args->command != 0xFF) {
                    fprintf(stderr, "Solo se permite un comando a la vez (Flags de comando: -a -m -s -U)\n"
                        "Use el flag -h para mas información\n");
                    exit(1);
                }
                args->command = 0x03;
                if(atoi(optarg) > 255) {
                    fprintf(stderr, "Tamaño máximo de pool es 255\n");
                    exit(1);
                }
                args->params.new_pool_size = atoi(optarg);
                break; 
            case 'v':
                version();
                exit(0);
                break;
            default:
                fprintf(stderr, "unknown argument %d.\n", c);
                exit(1);
        }

    }
    if (optind < argc) {
        fprintf(stderr, "argument not accepted: ");
        while (optind < argc) {
            fprintf(stderr, "%s ", argv[optind++]);
        }
        fprintf(stderr, "\n");
        exit(1);
    }
}
