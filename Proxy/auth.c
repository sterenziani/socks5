#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "auth.h"

extern void auth_parser_init (struct auth_parser *p){
  p->state = auth_version;
  p->remaining = 0;
  p->ulen = 0;
  p->plen = 0;
  //memset(p->username, 0x00, 256);
  //memset(p->password, 0x00, 256);
}

enum auth_state auth_parser_feed (struct auth_parser *p, uint8_t b){
  switch(p->state) {
      case auth_version:
          if(0x01 == b) {
              p->state = auth_ulen;
          } else {
              p->state = auth_error_unsupported_version;
          }
          break;

      case auth_ulen:
          p->remaining = b;
          p->state     = auth_user;

          if(p->remaining <= 0) {
              p->state = auth_plen;
          }
          break;

      case auth_user:
          p->username[p->ulen] = b;
          p->ulen++;
          p->remaining--;
          if(p->remaining <= 0) {
              p->state = auth_plen;
          }
          break;

      case auth_plen:
          p->remaining = b;
          p->state     = auth_pass;

          if(p->remaining <= 0) {
              p->state = auth_done;
          }
          break;

      case auth_pass:
          p->password[p->plen] = b;
          p->plen++;
          p->remaining--;
          if(p->remaining <= 0) {
            p->state = auth_done;
          }
          break;

      case auth_done:

      case auth_error_unsupported_version:
          // nada que hacer, nos quedamos en este estado
          break;
      default:
          fprintf(stderr, "unknown state %d\n", p->state);
          abort();
  }
  return p->state;
}

enum auth_state auth_consume(buffer *b, struct auth_parser *p, bool *errored){
  enum auth_state st = p->state;
  while(buffer_can_read(b)) {
      const uint8_t c = buffer_read(b);
      st = auth_parser_feed(p, c);
      if (auth_is_done(st, errored)) {
          break;
      }
  }
  return st;
}

bool auth_is_done(const enum auth_state state, bool *errored){
  bool ret;
  switch (state) {
      case auth_error_unsupported_version:
          if (0 != errored) {
              *errored = true;
          }
          /* no break */
      case auth_done:
          ret = true;
          break;
      default:
          ret = false;
          break;
  }
 return ret;
}


extern const char * auth_error(const struct auth_parser *p){
  char *ret;
  switch (p->state) {
      case auth_error_unsupported_version:
          ret = "unsupported version";
          break;
      default:
          ret = "";
          break;
  }
  return ret;
}

void auth_parser_close(struct auth_parser *p){
    /* no hay nada que liberar */
}


int auth_marshall(buffer *b, const uint8_t status){
  size_t n;
  uint8_t *buff = buffer_write_ptr(b, &n);
  if(n < 2) {
      return -1;
  }
  buff[0] = 0x01;
  buff[1] = status;
  buffer_write_adv(b, 2);
  return 2;
}
