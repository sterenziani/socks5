#include "passwords.h"

static char authorization[] = "AUTHORIZATION:";
static char basic[] = "BASIC";

void http_parser_init (struct http_parser *p){
  p->state = http_read;
  p->read = 0;
  memset(p->base64, 0x00, 682);
}

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
                                    else{
                                      p->state = http_read;
                                    }
                                    break;

    case http_read_authorization:   if(toupper(b) == authorization[p->read])
                                    {
                                      p->read++;
                                    }
                                    else{
                                      p->read = 0;
                                      p->state = http_read;
                                      break;
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


void pop3_parser_init (struct pop3_parser *p){
  p->state = pop3_read_welcome;
  p->encoded = false;
  p->read = 0;
  p->buff_length = 0;
  memset(p->buffer, 0x00, 682);
}

static char okay[] = "+OK";
static char auth[] = "AUTH ";
static char user[] = "USER ";
static char pass[] = "PASS ";

void pop3_clean_buffer(struct pop3_parser *p){
  memset(p->buffer, 0, p->buff_length);
  p->buff_length = 0;
}

enum pop3_parser_state pop3_parser_feed (struct pop3_parser *p, uint8_t b){
  switch(p->state){
    case pop3_read_welcome:     if(toupper(b) == okay[p->read])
                                {
                                  p->read++;
                                }
                                else{
                                  break;
                                }
                                if(p->read == strlen(okay) && b != 0x0d)
                                {
                                  p->read = 0;
                                  p->state = pop3_read;
                                }
                                else if(b == 0x0d)
                                {
                                  p->read = 0;
                                  p->state = pop3_line_break;
                                }
                                break;

    case pop3_read:             if(b == 0x0d)
                                {
                                  p->state = pop3_line_break;
                                }
                                if(b == 0x0a)
                                {
                                  p->state = pop3_read_command;
                                }
                                break;

    case pop3_line_break:       if(b == 0x0a)
                                {
                                  p->state = pop3_read_command;
                                }
                                break;

    case pop3_read_command:     if(toupper(b) == auth[0])
                                {
                                  p->read = 1;
                                  p->state = pop3_read_auth;
                                }
                                else if(toupper(b) == user[0])
                                {
                                  p->read = 1;
                                  p->state = pop3_read_user_com;
                                }
                                else
                                  p->state = pop3_read;
                                break;

    case pop3_read_auth:        break;

    case pop3_read_user_com:    if(toupper(b) == user[p->read])
                                {
                                  p->read++;
                                }
                                else{
                                  p->read = 0;
                                  p->state = pop3_read;
                                  break;
                                }
                                if(p->read == strlen(user))
                                {
                                  p->read = 0;
                                  p->state = pop3_read_user;
                                }
                                break;

    case pop3_read_user:        if(b == 0x0a)
                                {
                                  p->state = pop3_await_user_ok;
                                  p->read = 0;
                                  break;
                                }
                                p->buffer[p->buff_length] = b;
                                p->buff_length++;
                                break;

    case pop3_await_user_ok:    if(toupper(b) == okay[p->read])
                                {
                                  p->read++;
                                }
                                else{
                                  pop3_clean_buffer(p);
                                  p->state = pop3_read;
                                  break;
                                }
                                if(p->read == strlen(okay))
                                {
                                  p->state = pop3_user_ok_read;
                                }
                                break;

    case pop3_user_ok_read:     if(b == 0x0a)
                                {
                                  p->state = pop3_read_pass_com;
                                  p->read = 0;
                                  p->buffer[p->buff_length] = '\t';
                                  p->buff_length++;
                                }
                                break;

    case pop3_read_pass_com:    if(toupper(b) == pass[p->read])
                                {
                                  p->read++;
                                }
                                else if(toupper(b) == user[0])
                                {
                                  p->read = 1;
                                  p->state = pop3_read_user_com;
                                }
                                else{
                                  p->read = 0;
                                  pop3_clean_buffer(p);
                                  p->state = pop3_read;
                                  break;
                                }
                                if(p->read == strlen(pass))
                                {
                                  p->read = 0;
                                  p->state = pop3_read_pass;
                                }
                                break;

    case pop3_read_pass:        if(b == 0x0a)
                                {
                                  p->state = pop3_await_pass_ok;
                                  p->read = 0;
                                  break;
                                }
                                p->buffer[p->buff_length] = b;
                                p->buff_length++;
                                break;

    case pop3_await_pass_ok:    if(toupper(b) == okay[p->read])
                                {
                                  p->read++;
                                }
                                else{
                                  pop3_clean_buffer(p);
                                  p->state = pop3_read;
                                }
                                if(p->read == strlen(okay))
                                {
                                  p->state = pop3_user_success;
                                }
                                break;

    case pop3_user_success:
    case pop3_auth_success:
    case pop3_error:            break;
  }
  return p->state;
}

enum pop3_parser_state pop3_consume(buffer *b, struct pop3_parser *p){
  enum pop3_parser_state st = p->state;
  size_t bytes;
  uint8_t* ptr = buffer_read_ptr(b, &bytes);
  for (size_t i = 0; i < bytes; i++)
  {
    const uint8_t c = ptr[i];
    st = pop3_parser_feed(p, c);
    if (pop3_is_done(st)) {
        break;
    }
  }
  return st;
}

bool pop3_is_done(const enum pop3_parser_state state){
  bool ret;
  switch (state) {
      case pop3_error:
          ret = true;
          break;
      case pop3_user_success:
          ret = true;
          break;
      case pop3_auth_success:
          ret = true;
          break;
      default:
          ret = false;
          break;
  }
 return ret;
}

void pop3_parser_close(struct pop3_parser *p){

}
