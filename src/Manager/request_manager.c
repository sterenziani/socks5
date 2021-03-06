#include <stdio.h>
#include <stdlib.h>

#include "request_manager.h"
#define PROTOCOL_VERSION 0x01

extern void
request_manager_parser_init(struct request_manager_parser *p) {
    p->state     = request_version;
    p->remaining    = 0x00;
    p->total_users  = 0x00;
    p->user_number  = 0x00;
    p->pointer  = 0x00;
}

extern enum request_manager_state
request_manager_parser_feed(struct request_manager_parser *p, const uint8_t b) {
    switch(p->state) {
        case request_version:
            if(PROTOCOL_VERSION == b) {
                p->state = request_command;
            } else {
                p->state = request_error_unsupported_version;
            }
            break;

        case request_command:
            p->command = b;

            if(0x00 == b) {
                p->state = request_status;
            }
            else if(0x01 == b) {
                p->state = request_user_amount;
            }
            else if(0x02 == b) {
                p->state = request_total_con;
            }
            else if(0x03 == b) {
                p->state = request_status;
            }
            else {
                p->state = request_error_invalid_command;
            }
            break;

        case request_status:
            if(0x00 == b) {
                p->state = request_done;
            }
            else {
                p->state = request_error_no_changes;
            }
            break;

        case request_user_amount: ;
            p->state = request_user;
            p->total_users = b;
            break;

        case request_user:
            if(p->remaining == 0) {
                p->remaining = b;
            }
            else if(p->remaining == 1) {
                p->remaining = 0x00;
                p->users[p->user_number][p->pointer] = b;
                p->pointer = 0x00;
                p-> user_number ++;
                p->total_users --;
                if(p->total_users == 0x00) {
                    p->state = request_done;
                }
            }
            else {
                p->remaining --;
                p->users[p->user_number][p->pointer] = b;
                p->pointer ++;
            }
            break;

        case request_total_con:
            if(p->remaining == 0) {
                p->remaining = b;
            }
            else if(p->remaining == 1) {
                p->remaining = 0x00;
                p->total_con[p->pointer] = b;
                p->pointer = 0x00;
                p->state = request_active_con;
            }
            else {
                p->remaining --;
                p->total_con[p->pointer] = b;
                p->pointer ++;
            }
            break;

        case request_active_con:
            if(p->remaining == 0) {
                p->remaining = b;
            }
            else if(p->remaining == 1) {
                p->remaining = 0x00;
                p->active_con[p->pointer] = b;
                p->pointer = 0x00;
                p->state = request_bytes;
            }
            else {
                p->remaining --;
                p->active_con[p->pointer] = b;
                p->pointer ++;
            }
            break;

        case request_bytes:
            if(p->remaining == 0) {
                p->remaining = b;
            }
            else if(p->remaining == 1) {
                p->remaining = 0x00;
                p->bytes[p->pointer] = b;
                p->pointer = 0x00;
                p->state = request_done;
            }
            else {
                p->remaining --;
                p->bytes[p->pointer] = b;
                p->pointer ++;
            }
            break;

        case request_done:
        case request_error_unsupported_version:
            break;
        case request_error_invalid_command:
            break;
        case request_error_no_changes:
            break;
        default:
            fprintf(stderr, "Estado desconocido %d\n", p->state);
            abort();
    }

    return p->state;
}

extern bool
request_manager_is_done(const enum request_manager_state state, bool *errored) {
    bool ret;
    switch (state) {
        case request_error_unsupported_version:
            if (0 != errored) {
                *errored = true;
            }
        case request_error_invalid_command:
            if (0 != errored) {
                *errored = true;
            }
        case request_error_no_changes:
            if (0 != errored) {
                *errored = true;
            }
        case request_done:
            ret = true;
            break;
        default:
            ret = false;
            break;
    }
   return ret;
}

extern const char *
request_manager_error(const struct request_manager_parser *p) {
    char *ret;
    switch (p->state) {
        case request_error_unsupported_version:
            ret = "Versi??n no soportada";
            break;
        case request_error_invalid_command:
            ret = "Comando inv??lido";
            break;
        case request_error_no_changes:
            ret = "No se pudieron realizar cambios";
            break;
        default:
            ret = "";
            break;
    }
    return ret;
}

extern void
request_manager_parser_close(struct request_manager_parser *p) {
}

extern enum request_manager_state
request_manager_consume(buffer *b, struct request_manager_parser *p, bool *errored) {
    enum request_manager_state st = p->state;
    while(buffer_can_read(b)) {
        const uint8_t c = buffer_read(b);
        st = request_manager_parser_feed(p, c);
        if (request_manager_is_done(st, errored)) {
            break;
        }
    }
    return st;
}

extern int
request_marshall_new_user(buffer *b, const uint8_t user[], const int user_len,
    const uint8_t password[], const int pass_len) {
    size_t n;
    uint8_t *buff = buffer_write_ptr(b, &n);
    if(n < 6) {
        return -1;
    }
    buff[0] = PROTOCOL_VERSION;

    buff[1] = 0x00;

    buff[2] = user_len;
    for(int i = 0; i<user_len; i++) {
        buff[3 + i] = user[i];
    }

    buff[3 + user_len] = pass_len;
    for(int j = 0; j<pass_len; j++) {
        buff[4 + user_len + j] = password[j];
    }

    buffer_write_adv(b, user_len + pass_len + 4);
    return (user_len + pass_len + 4);
}

extern int
request_marshall_change_clients(buffer *b, const uint8_t size[]) {
    size_t n;
    unsigned int int_size = sizeof(unsigned int);
    uint8_t *buff = buffer_write_ptr(b, &n);
    if(n < 3) {
        return -1;
    }
    buff[0] = PROTOCOL_VERSION;
    buff[1] = 0x03;
    buff[2] = int_size;
    for(unsigned int i = 0; i<int_size; i++) {
        buff[3 + i] = size[i];
    }
    buffer_write_adv(b, 3 + int_size);
    return (3 + int_size);
}

extern int
request_marshall_get_info(buffer *b, const uint8_t command) {
    size_t n;
    uint8_t *buff = buffer_write_ptr(b, &n);
    if(n < 2) {
        return -1;
    }
    buff[0] = PROTOCOL_VERSION;
    buff[1] = command;

    buffer_write_adv(b, 2);
    return 2;
}
