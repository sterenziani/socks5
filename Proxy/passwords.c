#include "passwords.h"

void http_parser_init (struct http_parser *p){
  p->state = http_read;
  p->read = 0;
  memset(p->base64, 0x00, 682);
  memset(p->username, 0x00, 256);
  memset(p->password, 0x00, 256);
}

static char authorization[] = "AUTHORIZATION:";
static char basic[] = "BASIC";

enum http_parser_state http_parser_feed (struct http_parser *p, uint8_t b){
  switch(p->state){
    case http_read:                 if(b == 0x0d)
                                    {
                                      p->state = http_line_break;
                                    }
                                    break;

    case http_line_break:           if(b == 0x0a)
                                    {
                                      p->state = http_line_start;
                                    }
                                    break;

    case http_line_start:           if(toupper(b) == authorization[0])
                                    {
                                      p->state = http_read_authorization;
                                      p->read = 1;
                                    }
                                    else if(b == 0x0d)
                                    {
                                      p->state = http_line_break;
                                    }
                                    break;

    case http_read_authorization:   if(toupper(b) == authorization[p->read])
                                    {
                                      p->read++;
                                    }
                                    if(p->read == strlen(authorization))
                                    {
                                      p->state = http_authorization_space;
                                    }
                                    break;

    case http_authorization_space:  if(!isspace(b))
                                    {
                                      p->state = http_read_type;
                                      if(toupper(b) == basic[0])
                                        p->read = 1;
                                      else
                                        p->state = http_no_user;
                                    }
                                    break;

    case http_read_type:            if(toupper(b) == basic[p->read])
                                    {
                                      p->read++;
                                    }
                                    if(p->read == strlen(basic))
                                    {
                                      p->state = http_type_space;
                                    }
                                    break;

    case http_type_space:           if(!isspace(b))
                                    {
                                      p->state = http_read_base64;
                                      p->read = 0;
                                      p->base64[p->read] = b;
                                      p->read++;
                                    }
                                    break;

    case http_read_base64:          if(b == 0x0d || isspace(b))
                                      p->state = http_done;
                                    else
                                    {
                                      p->base64[p->read] = b;
                                      p->read++;
                                    }
                                    break;
    case http_done:
    case http_no_user:              break;

    default:                        fprintf(stderr, "unknown state %d\n", p->state);
                                    abort();
  }
  return p->state;
}

enum http_parser_state http_consume(buffer *b, struct http_parser *p){
  enum http_parser_state st = p->state;
  size_t bytes;
  uint8_t* ptr = buffer_read_ptr(b, &bytes);
  for (size_t i = 0; i < bytes; i++)
  {
    const uint8_t c = ptr[i];
    st = http_parser_feed(p, c);
    if (http_is_done(st)) {
        break;
    }
  }
  return st;
}


bool http_is_done(const enum http_parser_state state){
  bool ret;
  switch (state) {
      case http_no_user:
          ret = true;
          break;
      case http_done:
          ret = true;
          break;
      default:
          ret = false;
          break;
  }
 return ret;
}


void http_parser_close(struct http_parser *p){
  /* no hay nada que liberar */
}
