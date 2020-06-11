#include "parser_doh.h"

/* CDT del parser_doh */
struct parser_doh {

    // el status que devuelve el http response
    unsigned statusCode;

    // la longitud del dns-message
    size_t contentLength;

    // si es chunked, invalida el contentLength
    int is_chunked;

    // el tamaño del siguiente chunk
    size_t chunkLength;

    // el index del dns-message, útil para saber donde estamos parados
    size_t dnsIndex;

    // cantidad de questions, para saber cuanto saltear
    size_t dnsQuestions;

    // cantidad de answers, para ir preparando el addrinfo
    size_t dnsAnswers;

    // si el content type es valido
    int is_validContentType;

    // el ultimo evento
    unsigned status;

    // estado actual
    unsigned stage;

    // los parsers involucrados
    struct parser *parser_http;
    struct parser *parser_te;
    struct parser *parser_ct;
    struct parser *parser_cl;
    struct parser *parser_num;

    // definitions
    struct parser_definition *parser_definition_te;
    struct parser_definition *parser_definition_ct;
    struct parser_definition *parser_definition_cl;
};

struct parser_doh *
parser_doh_init(void){
  struct parser_doh *ret = malloc(sizeof(*ret));
  if(ret != NULL) {
      memset(ret, 0, sizeof(*ret));

      //ret->state = HTTP_BEFORE_CODE;

      ret->stage = STAGE_HTTP;

      struct parser_definition te = parser_utils_strcmpi(PARSER_STRING_TE);
      ret->parser_definition_te = malloc(sizeof(*ret->parser_definition_te));
      if(ret->parser_definition_te != NULL) {
        memcpy(ret->parser_definition_te,&te,sizeof(*ret->parser_definition_te));
      }

      struct parser_definition ct = parser_utils_strcmpi(PARSER_STRING_CT);
      ret->parser_definition_ct = malloc(sizeof(*ret->parser_definition_ct));
      if(ret->parser_definition_ct != NULL) {
        memcpy(ret->parser_definition_ct,&ct,sizeof(*ret->parser_definition_ct));
      }

      struct parser_definition cl = parser_utils_strcmpi(PARSER_STRING_CL);
      ret->parser_definition_cl = malloc(sizeof(*ret->parser_definition_cl));
      if(ret->parser_definition_cl != NULL) {
        memcpy(ret->parser_definition_cl,&cl,sizeof(*ret->parser_definition_cl));
      }

      ret->parser_http = parser_init(parser_no_classes(), &parser_http_definition);
      ret->parser_te = parser_init(parser_no_classes(), ret->parser_definition_te);
      ret->parser_ct = parser_init(parser_no_classes(), ret->parser_definition_ct);
      ret->parser_cl = parser_init(parser_no_classes(), ret->parser_definition_cl);
      ret->parser_num = parser_init(parser_no_classes(), &parser_num_definition);
  }
  return ret;
}

void
parser_doh_destroy(struct parser_doh *p) {
    if(p != NULL) {

      parser_destroy(p->parser_http);
      parser_destroy(p->parser_te);
      parser_destroy(p->parser_ct);
      parser_destroy(p->parser_cl);
      parser_destroy(p->parser_num);

      parser_utils_strcmpi_destroy(p->parser_definition_te);
      parser_utils_strcmpi_destroy(p->parser_definition_ct);
      parser_utils_strcmpi_destroy(p->parser_definition_cl);

      free(p->parser_definition_te);
      free(p->parser_definition_ct);
      free(p->parser_definition_cl);

      free(p);
    }
}

unsigned
parser_doh_feed(struct parser_doh *p, const uint8_t c){

  const struct parser_event *r, *r2;

  if(p->stage == STAGE_HTTP){

    p->status = HTTP_HEADER;

    r = parser_feed(p->parser_http,c);
    switch (r->type) {
      case HTTP_S_EVENT_PARSED_CODE:
      case HTTP_S_EVENT_PARSING_CODE: //read input number
        r2 = parser_feed(p->parser_num,c);
        switch (r2->type) {
          case NUMS_EVENT_OK:
            p->statusCode = p->statusCode * 10 + (c - '0');
            break;
          case NUMS_EVENT_END:
            p->status = HTTP_PARSED_CODE;
            parser_reset(p->parser_num);
            break;
        }
        break;
      case HTTP_S_EVENT_NOTHING:  // read with other parsers
        if(!p->is_validContentType){
          r2 = parser_feed(p->parser_ct,c);
          if(r2->type == STRING_CMP_EQ){
            p->is_validContentType = 1;
          }
        }
        if(!p->is_chunked){

          if(p->parser_cl->state == STRING_CMP_EQ){
            r2 = parser_feed(p->parser_num,c);
            switch (r2->type) {
              case NUMS_EVENT_OK:
                p->contentLength = p->contentLength * 10 + (c - '0');
                break;
              case NUMS_EVENT_END:
                parser_reset(p->parser_cl);
                parser_reset(p->parser_num);
                break;
            }
          }else{

            r2 = parser_feed(p->parser_cl,c);

            r2 = parser_feed(p->parser_te,c);
            if(r2->type == STRING_CMP_EQ){
              p->is_chunked = 1;
            }
          }
        }
        break;
      case HTTP_S_EVENT_CRLF: // reset other parsers
        if(!p->is_chunked){
          parser_reset(p->parser_cl);
          parser_reset(p->parser_te);
        }
        if(!p->is_validContentType){
          parser_reset(p->parser_ct);
        }
        break;
      case HTTP_S_EVENT_END:  // move to following stage
        p->stage = STAGE_DNS;
        p->status = DNS_MESSAGE;
        break;
    }
  }else if(p->stage == STAGE_DNS){
    p->status = DOH_FINISHED;
    p->stage = STAGE_END;
  }

  return p->status;
}

unsigned
parser_doh_getStatusCode(struct parser_doh *p){
  return p->statusCode;
}

int
parser_doh_getAddrInfo(struct parser_doh *p, struct addrinfo **res){
  // todo
  return 0;
}

int
parser_doh_isValidContentType(struct parser_doh *p){
  return p->is_validContentType;
}

// structs auxiliares
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

int
hexCharToInt(char c){
  int res = 0;
  if(c>='0' && c<='9'){
    res -= '0';
  }else if(toupper(c)>='A' && toupper(c)<='E'){
    res -= 'A';
    res += 10;
  }else{
    res = -1;
  }
  return res;
}
