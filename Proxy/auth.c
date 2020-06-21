#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "auth.h"

extern void auth_parser_init (struct auth_parser *p){
  p->state = auth_version;
  p->remaining = 0;
  p->ulen = 0;
  p->plen = 0;
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

// Retorna 0 si el usuario y contraseña son validos. 1 si no lo son.
int user_pass_valid(const char* u, int ulen, const char* p, int plen)
{
  char* user = malloc(ulen+1);
  char* pass = malloc(plen+1);
  memset(user, 0, ulen+1);
  memset(pass, 0, plen+1);
  memcpy(user, u, ulen);
  memcpy(pass, p, plen);
  for(int i=0; i < MAX_USERS; i++)
  {
    if(registered_users[i][0] != NULL && registered_users[i][1] != NULL)
    {
      if(strcmp(registered_users[i][0], user) == 0 && strcmp(registered_users[i][1], pass) == 0)
      {
        free(user);
        free(pass);
        return 0;
      }
    }
  }
  free(user);
  free(pass);
  return 1;
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
