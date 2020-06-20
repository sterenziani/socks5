#ifndef PARSER_HTTP_H
#define PARSER_HTTP_H

#include <stdlib.h>
#include <string.h>
#include <ctype.h>

#include "parser.h"

// definición de maquina

enum http_states {
    HTTP_S_BEFORE_CODE,
    HTTP_S_PARSING_CODE,
    HTTP_S_NO,
    HTTP_S_MAY_CRLF,
    HTTP_S_YES_CRLF,
    HTTP_S_MAY_END,
    HTTP_S_END
};

enum http_event_type {
    HTTP_S_EVENT_PARSING_CODE,
    HTTP_S_EVENT_PARSED_CODE,
    HTTP_S_EVENT_NOTHING,
    HTTP_S_EVENT_CRLF,
    HTTP_S_EVENT_END
};

static void
is_http_s_parsing_code(struct parser_event *ret, const uint8_t c) {
    ret->type    = HTTP_S_EVENT_PARSING_CODE;
    ret->n       = 1;
    ret->data[0] = c;
}

static void
is_http_s_parsed_code(struct parser_event *ret, const uint8_t c) {
    ret->type    = HTTP_S_EVENT_PARSED_CODE;
    ret->n       = 1;
    ret->data[0] = c;
}

static void
is_http_s_nothing(struct parser_event *ret, const uint8_t c) {
    ret->type    = HTTP_S_EVENT_NOTHING;
    ret->n       = 1;
    ret->data[0] = c;
}

static void
is_http_s_crlf(struct parser_event *ret, const uint8_t c) {
    ret->type    = HTTP_S_EVENT_CRLF;
    ret->n       = 1;
    ret->data[0] = c;
}

static void
is_http_s_end(struct parser_event *ret, const uint8_t c) {
    ret->type    = HTTP_S_EVENT_END;
    ret->n       = 1;
    ret->data[0] = c;
}

static const struct parser_state_transition HTTP_ST_BEFORE_CODE [] =  {
    {.when = ' ',        .dest = HTTP_S_PARSING_CODE,  .act1 = is_http_s_nothing,},
    {.when = ANY,        .dest = HTTP_S_BEFORE_CODE,   .act1 = is_http_s_nothing,},
};
static const struct parser_state_transition HTTP_ST_PARSING_CODE [] =  {
    {.when = '0',       .dest = HTTP_S_PARSING_CODE,  .act1 = is_http_s_parsing_code,},
    {.when = '1',       .dest = HTTP_S_PARSING_CODE,  .act1 = is_http_s_parsing_code,},
    {.when = '2',       .dest = HTTP_S_PARSING_CODE,  .act1 = is_http_s_parsing_code,},
    {.when = '3',       .dest = HTTP_S_PARSING_CODE,  .act1 = is_http_s_parsing_code,},
    {.when = '4',       .dest = HTTP_S_PARSING_CODE,  .act1 = is_http_s_parsing_code,},
    {.when = '5',       .dest = HTTP_S_PARSING_CODE,  .act1 = is_http_s_parsing_code,},
    {.when = '6',       .dest = HTTP_S_PARSING_CODE,  .act1 = is_http_s_parsing_code,},
    {.when = '7',       .dest = HTTP_S_PARSING_CODE,  .act1 = is_http_s_parsing_code,},
    {.when = '8',       .dest = HTTP_S_PARSING_CODE,  .act1 = is_http_s_parsing_code,},
    {.when = '9',       .dest = HTTP_S_PARSING_CODE,  .act1 = is_http_s_parsing_code,},
    {.when = '\r',       .dest = HTTP_S_MAY_CRLF,   .act1 = is_http_s_parsed_code,},
    {.when = ANY,        .dest = HTTP_S_NO,        .act1 = is_http_s_parsed_code,},
};
static const struct parser_state_transition HTTP_ST_NO [] =  {
    {.when = '\r',       .dest = HTTP_S_MAY_CRLF,  .act1 = is_http_s_nothing,},
    {.when = ANY,        .dest = HTTP_S_NO,        .act1 = is_http_s_nothing,},
};
static const struct parser_state_transition HTTP_ST_MAY_CRLF [] =  {
    {.when = '\n',       .dest = HTTP_S_YES_CRLF,  .act1 = is_http_s_crlf,},
    {.when = ANY,        .dest = HTTP_S_NO,        .act1 = is_http_s_nothing,},
};
static const struct parser_state_transition HTTP_ST_YES_CRLF [] =  {
    {.when = '\r',       .dest = HTTP_S_MAY_END,   .act1 = is_http_s_nothing,},
    {.when = ANY,        .dest = HTTP_S_NO,        .act1 = is_http_s_nothing,},
};
static const struct parser_state_transition HTTP_ST_MAY_END [] =  {
    {.when = '\n',       .dest = HTTP_S_END,       .act1 = is_http_s_end,},
    {.when = ANY,        .dest = HTTP_S_NO,        .act1 = is_http_s_nothing,},
};
static const struct parser_state_transition HTTP_ST_END [] =  {
    {.when = ANY,        .dest = HTTP_S_END,        .act1 = is_http_s_end,},
};

static const struct parser_state_transition *http_states [] = {
    HTTP_ST_BEFORE_CODE,
    HTTP_ST_PARSING_CODE,
    HTTP_ST_NO,
    HTTP_ST_MAY_CRLF,
    HTTP_ST_YES_CRLF,
    HTTP_ST_MAY_END,
    HTTP_ST_END
};

#define N(x) (sizeof(x)/sizeof((x)[0]))

static const size_t http_states_n [] = {
    N(HTTP_ST_BEFORE_CODE),
    N(HTTP_ST_PARSING_CODE),
    N(HTTP_ST_NO),
    N(HTTP_ST_MAY_CRLF),
    N(HTTP_ST_YES_CRLF),
    N(HTTP_ST_MAY_END),
    N(HTTP_ST_END)
};

static struct parser_definition parser_http_definition = {
    .states_count = N(http_states),
    .states       = http_states,
    .states_n     = http_states_n,
    .start_state  = HTTP_S_BEFORE_CODE,
};

static struct parser_definition parser_crlf_definition = {
    .states_count = N(http_states),
    .states       = http_states,
    .states_n     = http_states_n,
    .start_state  = HTTP_S_NO,
};

// get del parser

struct parser_definition
get_parser_http_definition(void);

struct parser_definition
get_parser_crlf_definition(void);

#endif // PARSER_HTTP_H
