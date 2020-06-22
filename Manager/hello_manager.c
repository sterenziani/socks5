#include <stdio.h>
#include <stdlib.h>

#include "hello_manager.h"

extern void 
hello_manager_parser_init(struct hello_manager_parser *p) {
    p->state     = hello_version;
}

extern enum hello_manager_state
hello_manager_parser_feed(struct hello_manager_parser *p, const uint8_t b) {
    switch(p->state) {
        case hello_version:
            if(0x01 == b) {
                p->state = hello_status;
            } else {
                p->state = hello_error_unsupported_version;
            }
            break;
        case hello_status:
            if(0x00 == b) {
                p->state = hello_done;
            }
            else {
                p->state = hello_error_invalid_user;
            }
            break;
        case hello_done:
        case hello_error_unsupported_version:
            break;
        case hello_error_invalid_user:
            break;
        default:
            fprintf(stderr, "unknown state %d\n", p->state);
            abort();
    }
    return p->state;
}

extern bool 
hello_manager_is_done(const enum hello_manager_state state, bool *errored) {
    bool ret;
    switch (state) {
        case hello_error_unsupported_version:
            if (0 != errored) {
                *errored = true;
            }
        case hello_error_invalid_user:
            if (0 != errored) {
                *errored = true;
            }
        case hello_done:
            ret = true;
            break;
        default:
            ret = false;
            break;
    }
   return ret;
}

extern const char *
hello_manager_error(const struct hello_manager_parser *p) {
    char *ret;
    switch (p->state) {
        case hello_error_unsupported_version:
            ret = "unsupported version";
            break;
        case hello_error_invalid_user:
            ret = "invalid user or password";
            break;
        default:
            ret = "";
            break;
    }
    return ret;
}

extern void 
hello__manager_parser_close(struct hello_manager_parser *p) {
}

extern enum hello_manager_state
hello_manager_consume(buffer *b, struct hello_manager_parser *p, bool *errored) {
    enum hello_manager_state st = p->state;
    while(buffer_can_read(b)) {
        const uint8_t c = buffer_read(b);
        st = hello_manager_parser_feed(p, c);
        if (hello_manager_is_done(st, errored)) {
            break;
        }
    }
    return st;
}

extern int
hello_manager_marshall(buffer *b, const uint8_t user[], const int user_len, 
    const uint8_t password[], const int pass_len) {
    size_t n;

    uint8_t *buff = buffer_write_ptr(b, &n);
    if(n < 5) {
        return -1;
    }

    buff[0] = 0x01;

    buff[1] = user_len;

    for(int i = 0; i<user_len; i++) {
        buff[2 + i] = user[i];
    }

    buff[2 + user_len] = pass_len;

    for(int j = 0; j<pass_len; j++) {
        buff[3 + user_len + j] = password[j];
    }

    buffer_write_adv(b, user_len + pass_len + 3);
    return (user_len + pass_len + 3);
}
