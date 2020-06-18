#include <stdlib.h>
#include <string.h>
#include <ctype.h>

#include "parser_http.h"

struct parser_definition
get_parser_http_definition(void) {
  return parser_http_definition;
}

struct parser_definition
get_parser_crlf_definition(void) {
  return parser_crlf_definition;
}
