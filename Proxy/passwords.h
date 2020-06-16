#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <stdbool.h>
#include <ctype.h>
#include "buffer.h"

enum http_parser_state {
    http_read,
    http_line_break,
    http_line_start,
    http_read_authorization,
    http_authorization_space,
    http_read_type,           // Solo soportamos Basic
    http_type_space,
    http_read_base64,
    http_done,
    http_no_user,
};

enum pop3_parser_state {
    pop3_read_welcome,
    pop3_line_break,
    pop3_line_start,
    pop3_read_command,  // Puede venir "CAPA" o "user santi-vm". Si lee "user ..." pasa a pop3_read_user. Si lee "AUTH_PLAIN" pasa a pop3_wait_nod
    pop3_wait_nod,      // Si leo "+ \n" paso a pop3_read_base64. El paquete contiene "2b 20 0d 0a"
    pop3_read_base64,   // Después de leer pasa a pop3_read_login
    pop3_read_user,     // Después de leer pasa a pop3_read_ok
    pop3_read_ok,       // Si leo "+ OK" paso a leer la contraseña. El paquete contiene "2b 4f 4b 0d 0a"
    pop3_read_pass,     // Después de leer pasa a pop3_read_login
    pop3_read_login,    // Si leo "2b 4f 4b 20 4c 6f 67 67 65 64 20 69 6e 2e 0d 0a" entonces se loggeó bien
    pop3_done,
    pop3_error,
};

struct http_parser {
    /** permite al usuario del parser almacenar sus datos */
    void *data;
    /******** zona privada *****************/
    enum http_parser_state state;
    /* metodos que faltan por leer */
    size_t read;
    char base64[682];
    char username[256];
    char password[256];
};


struct pop3_parser {
    void *data;
    enum pop3_parser_state state;
    char base64[682];
    char username[256];
    char password[256];
};

void http_parser_init (struct http_parser *p);
enum http_parser_state http_parser_feed (struct http_parser *p, uint8_t b);
enum http_parser_state http_consume(buffer *b, struct http_parser *p);
bool http_is_done(const enum http_parser_state state);
extern const char * http_error(const struct http_parser *p);
void http_parser_close(struct http_parser *p);

/*
void pop3_parser_init (struct pop3_parser *p);
enum pop3_state http_parser_feed (struct pop3_parser *p, uint8_t b);
enum pop3_state auth_consume(buffer *b, struct pop3_parser *p, bool *errored);
bool pop3_is_done(const enum pop3_state state, bool *errored);
extern const char * pop3_error(const struct pop3_parser *p);
void pop3_parser_close(struct pop3_parser *p);
*/
