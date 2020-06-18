#include "parser_doh.h"

/* CDT del parser_doh */
struct parser_doh {

    // el status_http que devuelve el http response
    unsigned statusCode;

    // la longitud del dns-message
    size_t contentLength;

    // si es chunked, invalida el contentLength
    int is_chunked;

    // el tamaño del siguiente chunk
    size_t chunkLength;

    // cantidad de questions, para saber cuanto saltear
    size_t dnsQuestions;

    // cantidad de answers, para ir preparando el addrinfo
    size_t dnsAnswers;

    // para saber si content type es reliable
    int is_connectionClose;

    // si el content type es valido
    int is_validContentType;

    // el ultimo evento (a nivel http)
    unsigned status_http;

    // estado a nivel dns
    unsigned status_dns;

    // el index del dns-message, útil para saber donde estamos parados
    size_t dnsIndex;

    // memory index, útil para hacer acciones con "x lugares alejados"
    size_t prev_dnsIndex;

    // el response type
    unsigned dnsResponseType;

    // el response RDLENGTH
    size_t dnsRDLength;

    // el index del sa_addr
    unsigned dnsRDATA;

    // estado actual
    unsigned stage;

    // addrinfo, the "head" of the linked list
    struct addrinfo *addrInfo_root;

    // addrinfo, the one currently being worked on
    struct addrinfo *addrInfo_curr;

    // los parsers involucrados
    struct parser *parser_http;
    struct parser *parser_crlf;
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
      ret->parser_crlf = parser_init(parser_no_classes(), &parser_crlf_definition);
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
      parser_destroy(p->parser_crlf);
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
            p->status_http = HTTP_PARSED_CODE;
            if(p->statusCode < 200 || p->statusCode >= 300){
              p->stage = STAGE_ERROR;
              p->status_http = HTTP_INVALID_CODE;
            }
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

          if(p->status_http == HTTP_PARSING_CL){
            r2 = parser_feed(p->parser_num,c);
            switch (r2->type) {
              case NUMS_EVENT_OK:
                p->contentLength = p->contentLength * 10 + (c - '0');
                break;
              case NUMS_EVENT_END:
                p->status_http = HTTP_HEADER;
                parser_reset(p->parser_cl);
                parser_reset(p->parser_num);
                break;
            }
          }else{

            r2 = parser_feed(p->parser_cl,c);
            if(r2->type == STRING_CMP_EQ){
              p->status_http = HTTP_PARSING_CL;
            }

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
        if(p->is_validContentType){
          p->stage = STAGE_DNS;
          p->status_http = DNS_MESSAGE;
          if(p->is_chunked == 0 && p->contentLength == 0){
            p->is_connectionClose = 1;
          }
        }else{
          p->stage = STAGE_ERROR;
          p->status_http = HTTP_INVALID_CT;
        }
        break;
    }
  }else if(p->stage == STAGE_DNS){

    // trabajando sobre stage dns, chunked no existe (por ahora)
    if(p->contentLength || p->is_connectionClose){
      if(p->dnsIndex<12){
        p->status_dns = DNS_HEADER;

        switch (p->dnsIndex) {
          case 11:  // la cantidad de Adiditional RRs
          case 10:
            break;
          case 9: // la cantidad de NS RRs
          case 8:
            break;
          case 7: // la cantidad de Answer RRs
            p->dnsAnswers*=0x10;
          case 6:
            p->dnsAnswers += c;
            break;
          case 5: // cantidad de Question RRs
            p->dnsQuestions*=0x10;
          case 4:
            p->dnsQuestions += c;
            break;
          case 3: // flags, importa el 1ro y los 4 ultimos
            if((c & 0x0E) != 0x00){
              p->stage = STAGE_ERROR;
              perror("Reply code not 0x0: \n");
            }
            break;
          case 2:
            break;
          case 1: // el id, lo ignoro
          case 0:
            break;
        }
      }else{
        switch (p->status_dns) {
          case DNS_HEADER:
            p->status_dns = DNS_QUESTION_NAME;
          case DNS_QUESTION_NAME:
            if(c == 0x00){
              p->status_dns = DNS_QUESTION_TYPE_AND_CLASS;
              p->prev_dnsIndex = p->dnsIndex;
            }
            break;
          case DNS_QUESTION_TYPE_AND_CLASS:
            if(p->dnsIndex-p->prev_dnsIndex >= 4){
              if(p->dnsAnswers>0){
                p->status_dns = DNS_ANSWER_NAME;
                p->prev_dnsIndex = p->dnsIndex+1;
              }else{
                // no answers
                p->status_http = DOH_FINISHED;
                p->stage = STAGE_END;
              }
            }
            break;
          case DNS_ANSWER_NAME:

            // reseteo el response type
            p->dnsResponseType = 0;
            p->dnsRDLength = 0;
            p->dnsRDATA = 0;

            // actualizo el current
            if(p->addrInfo_root==NULL){
              p->addrInfo_root = malloc(sizeof(*(p->addrInfo_root)));
              memset(p->addrInfo_root,0,sizeof(*(p->addrInfo_root)));
              p->addrInfo_curr = p->addrInfo_root;

              p->addrInfo_curr->ai_addr = malloc(sizeof(struct sockaddr_storage));
              memset(p->addrInfo_curr->ai_addr,0,sizeof(struct sockaddr_storage));
            }

            if(p->prev_dnsIndex == p->dnsIndex){
              // primera vez, tengo que revisar si soy con memoria o si tengo que leer
              if((c&0xc0) == 0xc0){
                // tengo el puntero
                p->prev_dnsIndex = 0;
              }else if((c&0xc0) == 0x00){
                // tengo que leer, la posición del prev indica si leer o no
                p->prev_dnsIndex = p->dnsIndex;
              }else{
                //error
                perror("dns packet has invalid format\n");
                p->stage=STAGE_ERROR;
              }
            }else{
              // segunda vez entrando.
              //  CASO puntero: el prev_dnsIndex == 0
              //  CASO nombre: queda el 0x00 como ultimo octeto
              if(p->prev_dnsIndex==0 || c == 0x00){
                p->status_dns = DNS_ANSWER_TYPE_AND_CLASS;
                p->prev_dnsIndex = p->dnsIndex+1;
              }
            }
            break;

          case DNS_ANSWER_TYPE_AND_CLASS:
            switch (p->dnsIndex-p->prev_dnsIndex) {
              case 3: // class
                p->status_dns = DNS_TTL;
                p->prev_dnsIndex = p->dnsIndex;
                // dns response type esta definido
                switch (p->dnsResponseType) {
                  case 0x0001:  // ipv4
                    p->addrInfo_curr->ai_family = AF_INET;
                    p->addrInfo_curr->ai_addrlen = (size_t) sizeof(struct sockaddr_in);
                    ((struct sockaddr_storage*)p->addrInfo_curr->ai_addr)->ss_family = AF_INET;
                    break;
                  case 0x001c:  // ipv6
                    p->addrInfo_curr->ai_family = AF_INET6;
                    p->addrInfo_curr->ai_addrlen = (size_t) sizeof(struct sockaddr_in6);
                    ((struct sockaddr_storage*)p->addrInfo_curr->ai_addr)->ss_family = AF_INET6;
                    break;
                  case 0x0005:
                    p->addrInfo_curr->ai_flags = AI_CANONNAME;
                  default:
                    p->addrInfo_curr->ai_family = AF_UNSPEC;
                    //free(p->addrInfo_curr->ai_addr);
                }
                break;
              case 2:
                break;
              case 1: //type
                p->dnsResponseType *= 0x10;
              case 0:
                p->dnsResponseType += c;
                break;
            }
            break;
          case DNS_TTL:
            if(p->dnsIndex-p->prev_dnsIndex >= 4){
              p->prev_dnsIndex = p->dnsIndex+1;
              p->status_dns = DNS_RDLENGTH;
            }
            break;
          case DNS_RDLENGTH:
            switch (p->dnsIndex-p->prev_dnsIndex){
              case 1:
                p->status_dns = DNS_RDATA;
                p->prev_dnsIndex = p->dnsIndex+1;
                p->dnsRDLength *= 0x10;
              case 0:
                p->dnsRDLength += c;
                break;
            }
            break;
          case DNS_RDATA:
            if(p->dnsRDLength--){
              if(p->addrInfo_curr->ai_family == AF_INET){
                memcpy(((char *) &((struct sockaddr_in*)p->addrInfo_curr->ai_addr)->sin_addr.s_addr)+p->dnsRDATA++,&c,sizeof(c));
              }else if(p->addrInfo_curr->ai_family == AF_INET6){
                ((struct sockaddr_in6*)p->addrInfo_curr->ai_addr)->sin6_addr.s6_addr[p->dnsRDATA++] = c;
              }

              if(p->dnsRDLength==0){
                p->status_dns = DNS_FINISHED_AN_ANSWER; // quiero ir al siguiente case
              }
            }
          case DNS_FINISHED_AN_ANSWER:
            if(p->status_dns == DNS_FINISHED_AN_ANSWER){

              // para validar que realmente debo estar aqui, tiene que ver con el caso anterior
              // armar el struct
              if(--p->dnsAnswers>0){
                p->prev_dnsIndex = p->dnsIndex+1;
                p->status_dns = DNS_ANSWER_NAME;

                // nuevo current
                p->addrInfo_curr->ai_next = malloc(sizeof(*(p->addrInfo_curr)));
                p->addrInfo_curr = p->addrInfo_curr->ai_next;
                memset(p->addrInfo_curr,0,sizeof(struct addrinfo));

                p->addrInfo_curr->ai_addr = malloc(sizeof(struct sockaddr_storage));
                memset(p->addrInfo_curr->ai_addr,0,sizeof(struct sockaddr_storage));
              }else{
                p->status_dns = DNS_FINISHED;
                p->status_http = DOH_FINISHED;
                p->stage = STAGE_END;
              }

            }
            break;
        }
      }

      // para avanzar el index
      p->dnsIndex++;
      p->contentLength--;
    }else if(p->is_chunked){
      // hacer el parseo de chunked
      const struct parser_event *r;
      r = parser_feed(p->parser_crlf,c);
      switch (r->type) {
        case HTTP_S_EVENT_CRLF:
          //crlf de len
          p->contentLength = p->chunkLength;
          break;
        case HTTP_S_EVENT_END:
          //parsee mensaje
          parser_reset(p->parser_crlf);
          if(p->chunkLength==0){
            // no mas contenido
            p->status_http = DOH_FINISHED;
            p->stage = STAGE_END;
          }else{
            p->chunkLength=0;
          }
          break;
        case HTTP_S_EVENT_NOTHING:  //  tengo un numero
        default:
          if(c != '\r'){
            int aux = hexCharToInt(c);
            if(aux<0){
              p->stage = STAGE_ERROR;
              p->status_http = DNS_ERROR;
            }else{
              p->chunkLength = p->chunkLength * 0x10 + aux;
            }
          }
      }
    }else{
      // termine
      p->status_http = DOH_FINISHED;
      p->stage = STAGE_END;
    }
  }

  return p->stage;
}

unsigned
parser_doh_getStatusCode(struct parser_doh *p){
  return p->statusCode;
}

struct addrinfo *
parser_doh_getAddrInfo(struct parser_doh *p, int *err){
  if(p->stage == STAGE_END){
    *err = 0;
  }else{
    *err = -1;
  }
  return p->addrInfo_root;
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
