#include <stdint.h>
#include <stdbool.h>
#include "buffer.h"

enum request_state {
    request_version,
    request_command,
    request_rsv,
    request_atyp,
    request_dest_addr,
    request_dest_port,
    request_done,
    request_error_unsupported_version,
    request_error_unsupported_command,
    request_error_reserved,
    request_error_unsupported_addr_type,
    request_error_invalid_address,
    request_error_invalid_port,
    request_error_mem_alloc,
};

enum request_error_code {
    request_success = 0x00,
    request_socks_fail = 0x01,
    request_connection_fail = 0x05,
    request_unsupported_cmd = 0x07,
    request_unsupported_atyp = 0x08,
};

enum request_command {
	req_connect = 0x01,
	req_bind = 0x02,
	req_udp_associate = 0x03,
};

enum request_address_type {
	ipv4 = 0x01,
	domain = 0x03,
	ipv6 = 0x04,
};

struct request_parser {
    void *data;
    /******** zona privada *****************/
    enum request_state state;
    enum request_command command;
    enum request_address_type address_type;
    enum request_error_code error;
    uint8_t port[2];
    uint8_t address[255];
    uint8_t remaining;
    uint8_t addr_ptr;

};

/** inicializa el parser */
void request_parser_init (struct request_parser *p);

/** entrega un byte al parser. retorna true si se llego al final  */
enum request_state request_parser_feed (struct request_parser *p, uint8_t b);

/**
 * por cada elemento del buffer llama a `request_parser_feed' hasta que
 * el parseo se encuentra completo o se requieren mas bytes.
 *
 * @param errored parametro de salida. si es diferente de NULL se deja dicho
 *   si el parsing se debió a una condición de error
 */
enum request_state
request_consume(buffer *b, struct request_parser *p, bool *errored);

/**
 * Permite distinguir a quien usa request_parser_feed si debe seguir
 * enviando caracters o no. 
 *
 * En caso de haber terminado permite tambien saber si se debe a un error
 */
bool 
request_is_done(const enum request_state state, bool *errored);

/**
 * En caso de que se haya llegado a un estado de error, permite obtener una
 * representación textual que describe el problema
 */
extern const char *
request_error(const struct request_parser *p);


/** libera recursos internos del parser */
void request_parser_close(struct request_parser *p);


/**
 * serializa en buff la respuesta al request.
 *
 * Retorna la cantidad de bytes ocupados del buffer o -1 si no había
 * espacio suficiente.
 */
int
request_marshall(buffer *b, const uint8_t reply);
