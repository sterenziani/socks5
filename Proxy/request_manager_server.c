#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "request_manager_server.h"

extern void 
request_manager_server_parser_init(struct request_manager_server_parser *p) {
    p->state     = request_server_version;
    p->remaining    = 0x00;
    p->pointer  = 0x00;
    p->pool_size = 0x00;
}

extern enum request_manager_server_state
request_manager_server_parser_feed(struct request_manager_server_parser *p, const uint8_t b) {
    switch(p->state) {
        case request_server_version:
            if(0x05 == b) {
                p->state = request_server_status;
            } else {
                p->state = request_server_error_unsupported_version;
            }
            break;

        case request_server_command:
            p->command = b;
            if(0x00 == b) {
                p->state = request_server_user;
            }
            else if(0x01 == b) {
                p->state = request_server_done;
            }
            else if(0x02 == b) {
                p->state = request_server_done;
            }
            else if(0x03 == b) {
                p->state = request_server_size;
            }
            else {
                p->state = request_server_error_invalid_command;
            }
            break;

        case request_server_user:
            if(p->remaining == 0) {
                p->remaining = b;
            }
            else if(p->remaining == 1) {
                p->remaining = 0x00;
                p->user[p->pointer] = b;
                p->pointer = 0x00;
                p->state = request_server_pass;
            }
            else {
                p->remaining --;
                p->user[p->pointer] = b;
                p->pointer ++;
            }
            break;

        case request_server_pass:
            if(p->remaining == 0) {
                p->remaining = b;
            }
            else if(p->remaining == 1) {
                p->remaining = 0x00;
                p->pass[p->pointer] = b;
                p->pointer = 0x00;
                p->state = request_server_done;
            }
            else {
                p->remaining --;
                p->pass[p->pointer] = b;
                p->pointer ++;
            }
            break;

        case request_server_size:
            p->pool_size = b;
            p->state = request_server_done;
            break;

        case request_server_done:
        case request_server_error_unsupported_version:
            break;
        case request_server_error_invalid_command:
            break;
        default:
            fprintf(stderr, "unknown state %d\n", p->state);
            abort();
    }

    return p->state;
}

extern bool 
request_manager_server_is_done(const enum request_manager_server_state state, bool *errored) {
    bool ret;
    switch (state) {
        case request_server_error_unsupported_version:
            if (0 != errored) {
                *errored = true;
            }
        case request_server_error_invalid_command:
            if (0 != errored) {
                *errored = true;
            }
        case request_server_done:
            ret = true;
            break;
        default:
            ret = false;
            break;
    }
   return ret;
}

extern const char *
request_manager_server_error(const struct request_manager_server_parser *p) {
    char *ret;
    switch (p->state) {
        case request_server_error_unsupported_version:
            ret = "unsupported version";
            break;
        case request_server_error_invalid_command:
            ret = "invalid command";
            break;
        default:
            ret = "";
            break;
    }
    return ret;
}

extern enum request_manager_server_state 
request_manager_server_consume(buffer *b, struct request_manager_server_parser *p, bool *errored) {
    enum request_manager_server_state st = p->state;
    while(buffer_can_read(b)) {
        const uint8_t c = buffer_read(b);
        st = request_manager_server_parser_feed(p, c);
        if (request_manager_server_is_done(st, errored)) {
            break;
        }
    }
    return st;
}

extern int
request_marshall_change(buffer *b, const uint8_t status, const uint8_t command) {
    size_t n;
    uint8_t *buff = buffer_write_ptr(b, &n);
    if(n < 3) {
        return -1;
    }
    buff[0] = 0x05;

    buff[1] = command;

    buff[2] = status;

    buffer_write_adv(b, 3);
    return 3;
}

extern int
request_marshall_send_list(buffer *b, char* users[MAX_USERS][2]) {
    size_t n;
    uint8_t *buff = buffer_write_ptr(b, &n);
    if(n < 5) {
        return -1;
    }
    buff[0] = 0x05;
    buff[1] = 0x01;
    int buff_position = 3;
    unsigned int i = 0;
    for(; users[i][0] != NULL; i++) {
        buff[buff_position] = strlen(users[i][0]);
        buff_position ++;
        for(unsigned int j = 0; j < strlen(users[i][0]); j++) {
            buff[buff_position] = users[i][0][j] ;
            buff_position ++;
        }

    }

    buff[2] = i;

    buffer_write_adv(b, buff_position - 1);
    return (buff_position - 1);
}

extern int
request_marshall_send_metrics(buffer *b, const uint8_t t_connections[],
    const uint8_t a_connections[], const uint8_t bytes[]) {
    size_t n;
    uint8_t *buff = buffer_write_ptr(b, &n);
    if(n < 8) {
        return -1;
    }
    buff[0] = 0x05;
    buff[1] = 0x02;
    buff[2] = sizeof(unsigned long);

    unsigned int i = 0;
    unsigned int j = 0;
    unsigned int k = 0;

    for(; i < sizeof(unsigned long); i++) {
        buff[3 + i] = t_connections[i];
    }

    buff[3 + i] = sizeof(unsigned long);;

    for(; j < sizeof(unsigned long); j++) {
        buff[4 + i +j] = a_connections[j];
    }

    buff[4 + i + j] = sizeof(unsigned long);;

    for(; k < sizeof(unsigned long); k++) {
        buff[5 + i + j +k] = bytes[k];
    }

    buffer_write_adv(b, 4 + i + j + k);
    
    return (4 + i + j + k);
}
