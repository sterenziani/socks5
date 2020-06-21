#include <stdint.h>
#include <stdbool.h>

#include "../Proxy/buffer.h"

enum hello_manager_state {
    hello_version,
    hello_status,
    hello_done,
    hello_error_unsupported_version,
    hello_error_invalid_user,
};

struct hello_manager_parser {
    enum hello_manager_state state;
};

void hello_manager_parser_init (struct hello_manager_parser *p);

enum hello_manager_state hello_manager_parser_feed (struct hello_manager_parser *p, uint8_t b);


enum hello_manager_state
hello_manager_consume(buffer *b, struct hello_manager_parser *p, bool *errored);


bool 
hello_manager_is_done(const enum hello_manager_state state, bool *errored);

/**
 * En caso de que se haya llegado a un estado de error, permite obtener una
 * representación textual que describe el problema
 */
extern const char *
hello_manager_error(const struct hello_manager_parser *p);


void hello_manager_parser_close(struct hello_manager_parser *p);

int
hello_manager_marshall(buffer *b, const uint8_t user[], const int user_len, 
    const uint8_t password[], const int pass_len);
