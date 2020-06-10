#ifndef PARSER_NUM_H
#define PARSER_NUM_H

#include <stdlib.h>
#include <string.h>
#include <ctype.h>

#include "parser.h"

// definición de maquina

enum num_states {
    NUMS_NUM,
    NUMS_R,
    NUMS_INV,
    NUMS_END
};

enum num_event_type {
    NUMS_EVENT_OK,
    NUMS_EVENT_ERROR,
    NUMS_EVENT_END
};

static void
is_NUMS_ok(struct parser_event *ret, const uint8_t c) {
    ret->type    = NUMS_EVENT_OK;
    ret->n       = 1;
    ret->data[0] = c;
}

static void
is_NUMS_error(struct parser_event *ret, const uint8_t c) {
    ret->type    = NUMS_EVENT_ERROR;
    ret->n       = 1;
    ret->data[0] = c;
}

static void
is_NUMS_end(struct parser_event *ret, const uint8_t c) {
    ret->type    = NUMS_EVENT_END;
    ret->n       = 1;
    ret->data[0] = c;
}

static const struct parser_state_transition NUMST_NUM [] =  {
    {.when = '0',        .dest = NUMS_NUM,        .act1 = is_NUMS_ok,},
    {.when = '1',        .dest = NUMS_NUM,        .act1 = is_NUMS_ok,},
    {.when = '2',        .dest = NUMS_NUM,        .act1 = is_NUMS_ok,},
    {.when = '3',        .dest = NUMS_NUM,        .act1 = is_NUMS_ok,},
    {.when = '4',        .dest = NUMS_NUM,        .act1 = is_NUMS_ok,},
    {.when = '5',        .dest = NUMS_NUM,        .act1 = is_NUMS_ok,},
    {.when = '6',        .dest = NUMS_NUM,        .act1 = is_NUMS_ok,},
    {.when = '7',        .dest = NUMS_NUM,        .act1 = is_NUMS_ok,},
    {.when = '8',        .dest = NUMS_NUM,        .act1 = is_NUMS_ok,},
    {.when = '9',        .dest = NUMS_NUM,        .act1 = is_NUMS_ok,},
    {.when = '\r',       .dest = NUMS_R,          .act1 = is_NUMS_end,},
    {.when = ANY,        .dest = NUMS_INV,        .act1 = is_NUMS_error,},
};
static const struct parser_state_transition NUMST_R [] =  {
    {.when = '\n',       .dest = NUMS_END,       .act1 = is_NUMS_end,},
    {.when = ANY,        .dest = NUMS_INV,       .act1 = is_NUMS_error,},
};
static const struct parser_state_transition NUMST_INV [] =  {
    {.when = ANY,        .dest = NUMS_INV,        .act1 = is_NUMS_error,},
};
static const struct parser_state_transition NUMST_END [] =  {
    {.when = ANY,        .dest = NUMS_INV,        .act1 = is_NUMS_error,},
};

static const struct parser_state_transition *num_states [] = {
    NUMST_NUM,
    NUMST_R,
    NUMST_INV,
    NUMST_END,
};

#define N(x) (sizeof(x)/sizeof((x)[0]))

static const size_t num_states_n [] = {
    N(NUMST_NUM),
    N(NUMST_R),
    N(NUMST_INV),
    N(NUMST_END),
};

static struct parser_definition parser_num_definition = {
    .states_count = N(num_states),
    .states       = num_states,
    .states_n     = num_states_n,
    .start_state  = NUMS_NUM,
};

// get del parser

struct parser_definition
get_parser_num_definition(void);

#endif // PARSER_NUM_H
