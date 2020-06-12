#ifndef PARSER_DOH_H
#define PARSER_DOH_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>

#include "parser.h"
#include "parser_utils.h"
#include "parser_num.h"
#include "parser_http.h"

// strings relevantes

#define PARSER_STRING_TE "Transfer-Encoding: chunked"
#define PARSER_STRING_CT "Content-Type: application/dns-message"
#define PARSER_STRING_CL "Content-Length: "

// stage actual
enum doh_stage {
    STAGE_ERROR,
    STAGE_HTTP,
    STAGE_DNS,
    STAGE_END
};

enum doh_status{
    HTTP_PARSED_CODE,
    HTTP_HEADER,
    HTTP_INVALID_CODE,
    HTTP_INVALID_CT,
    HTTP_PARSING_CL,
    HTTP_CHUNK_NUM,
    HTTP_CHUNK_CR,
    DNS_MESSAGE,
    DNS_ERROR,
    DOH_FINISHED
};

enum dns_status{
    DNS_HEADER,
    DNS_QUESTION_NAME,
    DNS_QUESTION_TYPE_AND_CLASS,
    DNS_ANSWER_NAME,
    DNS_ANSWER_TYPE_AND_CLASS,
    DNS_TTL,
    DNS_RDLENGTH,
    DNS_RDATA,
    DNS_FINISHED_AN_ANSWER,
    DNS_FINISHED
};

// funciones relacionadas para parsear el doh

// inicia el parser doh
struct parser_doh *
parser_doh_init(void);

// libera todos los recursos vinculados al parser doh
void
parser_doh_destroy(struct parser_doh *p);

// alimenta el parser
unsigned
parser_doh_feed(struct parser_doh *p, const uint8_t c);

//getters
unsigned
parser_doh_getStatusCode(struct parser_doh *p);

int
parser_doh_isValidContentType(struct parser_doh *p);
/*
int
parser_doh_getAddrInfo(struct parser_doh *p, struct addrinfo **res);
*/

struct addrinfo *
parser_doh_getAddrInfo(struct parser_doh *p, int *err);

// get del parser de transfer encoding
struct parser_definition
get_parser_te_definition(void);

// get del parser de content type
struct parser_definition
get_parser_ct_definition(void);

// get del parser de content length
struct parser_definition
get_parser_cl_definition(void);

// para traducir en caso de chunks
int
hexCharToInt(char c);

#endif // PARSER_DOH_H
