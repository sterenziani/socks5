#include <stdlib.h>
#include <string.h>
#include <ctype.h>

#include "parser.h"
#include "parser_doh.h"

struct parser_definition
get_parser_te_definition(void) {
  return parser_utils_strcmpi(PARSER_STRING_TE);
}

struct parser_definition
get_parser_ct_definition(void) {
  return parser_utils_strcmpi(PARSER_STRING_CT);
}

struct parser_definition
get_parser_cl_definition(void) {
  return parser_utils_strcmpi(PARSER_STRING_CL);
}
