#include <stdlib.h>
#include <string.h>
#include <ctype.h>

#include "parser.h"
#include "parser_crlf.h"

struct parser_definition
get_parser_crlf_definition(void) {
  return parser_crlf_definition;
}
