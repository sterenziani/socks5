#include <stdint.h>
#include <stdbool.h>
#include "buffer.h"

#define MAX_USERS 10

enum request_manager_server_state {
    request_server_version,
    request_server_command,
    request_server_user,
    request_server_pass,
    request_server_size,
    request_server_done,
    request_server_error_unsupported_version,
    request_server_error_invalid_command,
};

struct request_manager_server_parser {
    enum request_manager_server_state state;

   	uint8_t user[255];
    uint8_t pass[255];

    uint8_t clients_size[4];

   	uint8_t remaining;
    uint8_t pointer;

   	uint8_t command;

};

void request_manager_server_parser_init (struct request_manager_server_parser *p);

enum request_manager_server_state 
request_manager_server_parser_feed (struct request_manager_server_parser *p, uint8_t b);


enum request_manager_server_state
request_manager_server_consume(buffer *b, struct request_manager_server_parser *p, bool *errored);


bool 
request_manager_server_is_done(const enum request_manager_server_state state, bool *errored);

/**
 * En caso de que se haya llegado a un estado de error, permite obtener una
 * representación textual que describe el problema
 */
extern const char *
request_manager_server_error(const struct request_manager_server_parser *p);


void request_manager_server_parser_close(struct request_manager_server_parser *p);

extern int
request_marshall_change(buffer *b, const uint8_t status, const uint8_t command);

extern int
request_marshall_send_list(buffer *b, char* users[MAX_USERS][2]);

extern int
request_marshall_send_metrics(buffer *b, const uint8_t t_connections[],
    const uint8_t a_connections[], const uint8_t bytes[]);