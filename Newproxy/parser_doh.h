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
    STAGE_HTTP,
    STAGE_DNS,
    STAGE_ERROR,
    STAGE_END
};

enum doh_staus{
    HTTP_PARSED_CODE,
    HTTP_HEADER,
    HTTP_INVALID_CODE,
    DNS_MESSAGE,
    DOH_FINISHED
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

int
parser_doh_getAddrInfo(struct parser_doh *p, struct addrinfo **res);

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
