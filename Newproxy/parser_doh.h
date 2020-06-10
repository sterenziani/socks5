#ifndef PARSER_DOH_H
#define PARSER_DOH_H

#include <stdlib.h>
#include <string.h>
#include <ctype.h>

#include "parser.h"
#include "parser_utils.h"

// strings relevantes

#define PARSER_STRING_TE "Transfer-Encoding: chunked"
#define PARSER_STRING_CT "Content-Type: application/dns-message"
#define PARSER_STRING_CL "Content-Length: "


// funciones relacionadas para parsear el doh

// get del parser de transfer encoding
struct parser_definition
get_parser_te_definition(void);

// get del parser de content type
struct parser_definition
get_parser_ct_definition(void);

// get del parser de content length
struct parser_definition
get_parser_cl_definition(void);

#endif // PARSER_DOH_H
