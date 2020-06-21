#ifndef ARGS_MANAGER_H_
#define ARGS_MANAGER_H

#include <stdlib.h> 
#include <stdint.h>

struct users {
    char *name;
    char *pass;
};

struct manager_args {
	struct users auth;

	uint8_t command;

	char           *socks_addr;
    unsigned short  socks_port;

    union {
    	struct users new_user;
    	int new_pool_size;
    } params;
}; 

void
parse_manager_args(const int argc, char **argv, struct manager_args *args);

#endif
