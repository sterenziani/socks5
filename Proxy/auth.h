#ifndef AUTH_H_Ds3wbvgeUHWkGm7B7QLXvXKoxlA
#define AUTH_H_Ds3wbvgeUHWkGm7B7QLXvXKoxlA

#include <stdint.h>
#include <stdbool.h>
#include "buffer.h"

enum auth_state {
    auth_version,
    auth_ulen,
    auth_user,
    auth_plen,
    auth_pass,
    auth_done,
    auth_error_unsupported_version,
};

struct auth_parser {
    /** permite al usuario del parser almacenar sus datos */
    void *data;
    /******** zona privada *****************/
    enum auth_state state;
    /* metodos que faltan por leer */
    uint8_t remaining;
    int ulen;
    int plen;
    char username[256];
    char password[256];
};


void auth_parser_init (struct auth_parser *p);
enum auth_state auth_parser_feed (struct auth_parser *p, uint8_t b);
enum auth_state auth_consume(buffer *b, struct auth_parser *p, bool *errored);
bool auth_is_done(const enum auth_state state, bool *errored);
extern const char * auth_error(const struct auth_parser *p);
void auth_parser_close(struct auth_parser *p);
int user_pass_valid(const char* u, int ulen, const char* p, int plen);
int auth_marshall(buffer *b, const uint8_t status);

#endif
