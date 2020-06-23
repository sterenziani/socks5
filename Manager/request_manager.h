#include <stdint.h>
#include <stdbool.h>
#include "../Proxy/buffer.h"

#define MAX_USERS 10

enum request_manager_state {
    request_version,
    request_command,
    request_status,
    request_user_amount,
    request_user,
    request_total_con,
    request_active_con,
    request_bytes,
    request_done,
    request_error_unsupported_version,
    request_error_invalid_command,
    request_error_no_changes,
};

struct request_manager_parser {
    enum request_manager_state state;

   	uint8_t users[MAX_USERS][255];

   	uint8_t remaining;
   	uint8_t total_users;
   	uint8_t user_number;
    uint8_t pointer;

   	uint8_t command;

   	uint8_t total_con[255];
   	uint8_t active_con[255];
   	uint8_t bytes[255];

};

void request_manager_parser_init (struct request_manager_parser *p);

enum request_manager_state request_manager_parser_feed (struct request_manager_parser *p, uint8_t b);


enum request_manager_state
request_manager_consume(buffer *b, struct request_manager_parser *p, bool *errored);


bool 
request_manager_is_done(const enum request_manager_state state, bool *errored);

/**
 * En caso de que se haya llegado a un estado de error, permite obtener una
 * representación textual que describe el problema
 */
extern const char *
request_manager_error(const struct request_manager_parser *p);


void request_manager_parser_close(struct request_manager_parser *p);

int
request_marshall_new_user(buffer *b, const uint8_t user[], const int user_len, 
    const uint8_t password[], const int pass_len);

int
request_marshall_change_clients(buffer *b, const uint8_t size[]);

int
request_marshall_get_info(buffer *b, const uint8_t command);
