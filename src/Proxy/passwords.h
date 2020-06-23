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
    pop3_read,
    pop3_line_break,
    pop3_read_command,
    // Para AUTH PLAIN
    pop3_read_auth,
    pop3_await_newline1,
    pop3_await_auth_go,
    pop3_await_newline2,
    pop3_read_base64,
    pop3_await_newline3,
    pop3_await_auth_ok,

    // PARA USER+PASS
    pop3_read_user_com,
    pop3_read_user,
    pop3_await_newline4,
    pop3_await_user_ok,
    pop3_user_ok_done,
    pop3_read_pass_com,
    pop3_read_pass,
    pop3_await_newline5,
    pop3_await_pass_ok,
    pop3_user_success,
    pop3_auth_success,
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
};


struct pop3_parser {
    void *data;
    enum pop3_parser_state state;
    char buffer[682];
    size_t read;
    size_t buff_length;
    bool encoded;
};

void http_parser_init (struct http_parser *p);
enum http_parser_state http_parser_feed (struct http_parser *p, uint8_t b);
enum http_parser_state http_consume(buffer *b, struct http_parser *p);
bool http_is_done(const enum http_parser_state state);
void http_parser_close(struct http_parser *p);


void pop3_parser_init (struct pop3_parser *p);
enum pop3_parser_state pop3_parser_feed (struct pop3_parser *p, uint8_t b);
enum pop3_parser_state pop3_consume(buffer *b, struct pop3_parser *p);
bool pop3_is_done(const enum pop3_parser_state state);
void pop3_parser_close(struct pop3_parser *p);
