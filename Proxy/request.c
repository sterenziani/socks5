#include <stdio.h>
#include <stdlib.h>

#include "request.h"

extern void request_parser_init(struct request_parser *p) {
    p->state     = request_version;
    p->remaining = 0;
    p->addr_ptr = 0;
    p->error = request_success;
}

extern enum request_state
request_parser_feed(struct request_parser *p, const uint8_t b) {
    switch(p->state) {
        case request_version:
            if(0x05 == b) {
                p->state = request_command;
            } else {
                p->state = request_error_unsupported_version;
            }
            break;
        case request_command:
        	p->state = request_rsv;
            if(0x01 == b) {
                p->command = req_connect;
            }
            else if(0x02 == b) {
                p->command = req_bind;
            }
            else if(0x03 == b) {
                p->command = req_udp_associate;
            }
            else {
                p->error = request_unsupported_cmd;
                p->state = request_error_unsupported_command;
            }
            break;
        case request_rsv:
        	if(0x00 == b) {
                p->state = request_atyp;
            } else {
                p->state = request_error_reserved;
            }
            break;
        case request_atyp:
            p->state = request_dest_addr;
            if(0x01 == b) {
                p->address_type = ipv4;
            }
            else if(0x03 == b) {
                p->address_type = domain;
            }
            else if(0x04 == b) {
                p->address_type = ipv6;
            }
            else {
                p->error = request_unsupported_atyp;
                p->state = request_error_unsupported_addr_type;
            }
            break;
        case request_dest_addr:
        	if(p->remaining == 0) {
        		if(p->address_type == ipv4) {
        			p->address[0] = b;
        			p->remaining = 3;
        			p->addr_ptr = 1;

        		}
        		else if(p->address_type == ipv6) {
                    p->address[0] = b;
        			p->remaining = 15;
        			p->addr_ptr = 1;
        		}
        		else if(p->address_type == domain) {
        			p->remaining = b;
        		}
        		else {
                	p->state = request_error_unsupported_addr_type;
        		}
        	}
        	else if(p->remaining == 1) {
                p->address[p->addr_ptr] = b;
        		p->remaining = 0;
        		p->addr_ptr ++;
            	p->state = request_dest_port;
        	}
            else if(p->remaining > 1) {
                p->address[p->addr_ptr] = b;
                p->remaining --;
                p->addr_ptr ++;
            }
        	else {
        		p->state = request_error_invalid_address;
        	}

        	break;
        case request_dest_port:
        	if(p->remaining == 0){
        		p->port[0] = b;
        		p->remaining = 1;
        	}
       		else if(p->remaining == 1){
       			p->port[1] = b;
       			p->remaining = 0;
       			p->state = request_done;
       		}
       		else {
        		p->state = request_error_invalid_port;
        	}
            break;
        case request_done:
        case request_error_unsupported_version:
            break;
        case request_error_unsupported_command:
            break;
        case request_error_unsupported_addr_type:
        	break;
        case request_error_invalid_port:
        	break;
        case request_error_invalid_address:
        	break;
        case request_error_mem_alloc:
        	break;
        case request_error_reserved:
            break;
        default:
            fprintf(stderr, "unknown state %d\n", p->state);
            abort();
    }

    return p->state;
}

extern bool
request_is_done(const enum request_state state, bool *errored) {
    bool ret;
    switch (state) {
        case request_error_unsupported_version:
            if (0 != errored) {
                *errored = true;
            }
        case request_error_unsupported_command:
            if (0 != errored) {
                *errored = true;
            }
        case request_error_reserved:
            if (0 != errored) {
                *errored = true;
            }
        case request_error_unsupported_addr_type:
            if (0 != errored) {
                *errored = true;
            }
        case request_error_invalid_address:
            if (0 != errored) {
                *errored = true;
            }
        case request_error_invalid_port:
            if (0 != errored) {
                *errored = true;
            }
        case request_error_mem_alloc:
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
request_error(const struct request_parser *p) {
    char *ret;
    switch (p->state) {
        case request_error_unsupported_version:
            ret = "unsupported version";
            break;
        case request_error_unsupported_command:
            ret = "unsupported command";
            break;
        case request_error_unsupported_addr_type:
            ret = "unsupported address type";
            break;
        case request_error_invalid_address:
            ret = "invalid address";
            break;
        case request_error_invalid_port:
            ret = "invalid port";
            break;
        case request_error_reserved:
            ret = "reserved's value must be 0x00";
        case request_error_mem_alloc:
        	ret = "memory allocation unsuccesful";
        break;
        default:
            ret = "";
            break;
    }
    return ret;
}

extern void
request_parser_close(struct request_parser *p) {
	free(p->address);
}

extern enum request_state
request_consume(buffer *b, struct request_parser *p, bool *errored) {
    enum request_state st = p->state;
    while(buffer_can_read(b)) {
        const uint8_t c = buffer_read(b);
        st = request_parser_feed(p, c);
        if (request_is_done(st, errored)) {
            break;
        }
    }
    return st;
}

extern int
request_marshall(buffer *b, const uint8_t reply) {
    size_t n;
    size_t i = 0;
    uint8_t *buff = buffer_write_ptr(b, &n);
    if(n < 10) {
        return -1;
    }
    buff[0] = 0x05;
    buff[1] = reply;
    buff[2] = 0x00;
    buff[3] = 0x01;
    for(;i < 4; i++) {
    	buff[4 + i] =  0;
    }
    buff[4 + i] = 0;
    buff[5 + i] = 0;
    buffer_write_adv(b, 10);
    return n;
}
