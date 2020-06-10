#ifndef PARSER_CRLF_H
#define PARSER_CRLF_H

#include <stdlib.h>
#include <string.h>
#include <ctype.h>

#include "parser.h"

// definición de maquina

enum crlf_states {
    CRLF_S_NO,
    CRLF_S_MAY_CRLF,
    CRLF_S_YES_CRLF,
    CRLF_S_MAY_END,
    CRLF_S_END
};

enum crlf_event_type {
    CRLF_S_EVENT_NOTHING,
    CRLF_S_EVENT_CRLF,
    CRLF_S_EVENT_END
};

static void
is_crlf_s_nothing(struct parser_event *ret, const uint8_t c) {
    ret->type    = CRLF_S_EVENT_NOTHING;
    ret->n       = 1;
    ret->data[0] = c;
}

static void
is_crlf_s_crlf(struct parser_event *ret, const uint8_t c) {
    ret->type    = CRLF_S_EVENT_CRLF;
    ret->n       = 1;
    ret->data[0] = c;
}

static void
is_crlf_s_end(struct parser_event *ret, const uint8_t c) {
    ret->type    = CRLF_S_EVENT_END;
    ret->n       = 1;
    ret->data[0] = c;
}

static const struct parser_state_transition CRLF_ST_NO [] =  {
    {.when = '\r',       .dest = CRLF_S_MAY_CRLF,  .act1 = is_crlf_s_nothing,},
    {.when = ANY,        .dest = CRLF_S_NO,        .act1 = is_crlf_s_nothing,},
};
static const struct parser_state_transition CRLF_ST_MAY_CRLF [] =  {
    {.when = '\n',       .dest = CRLF_S_YES_CRLF,  .act1 = is_crlf_s_crlf,},
    {.when = ANY,        .dest = CRLF_S_NO,        .act1 = is_crlf_s_nothing,},
};
static const struct parser_state_transition CRLF_ST_YES_CRLF [] =  {
    {.when = '\r',       .dest = CRLF_S_MAY_END,   .act1 = is_crlf_s_nothing,},
    {.when = ANY,        .dest = CRLF_S_NO,        .act1 = is_crlf_s_nothing,},
};
static const struct parser_state_transition CRLF_ST_MAY_END [] =  {
    {.when = '\n',       .dest = CRLF_S_END,       .act1 = is_crlf_s_end,},
    {.when = ANY,        .dest = CRLF_S_NO,        .act1 = is_crlf_s_nothing,},
};
static const struct parser_state_transition CRLF_ST_END [] =  {
    {.when = ANY,        .dest = CRLF_S_END,        .act1 = is_crlf_s_end,},
};

static const struct parser_state_transition *crlf_states [] = {
    CRLF_ST_NO,
    CRLF_ST_MAY_CRLF,
    CRLF_ST_YES_CRLF,
    CRLF_ST_MAY_END,
    CRLF_ST_END
};

#define N(x) (sizeof(x)/sizeof((x)[0]))

static const size_t crlf_states_n [] = {
    N(CRLF_ST_NO),
    N(CRLF_ST_MAY_CRLF),
    N(CRLF_ST_YES_CRLF),
    N(CRLF_ST_MAY_END),
    N(CRLF_ST_END)
};

static struct parser_definition parser_crlf_definition = {
    .states_count = N(crlf_states),
    .states       = crlf_states,
    .states_n     = crlf_states_n,
    .start_state  = CRLF_S_NO,
};

// get del parser

struct parser_definition
get_parser_crlf_definition(void);

#endif // PARSER_CRLF_H
