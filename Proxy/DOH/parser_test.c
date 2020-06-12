#include <stdio.h>
#include <stdlib.h>
#include <assert.h>
#include <errno.h>
#include <string.h>
#include <sys/types.h>

#include "../buffer.h"
#include "../parser.h"
#include "parser_num.h"
#include "parser_doh.h"
#include "parser_http.h"

#define TEST_BUFFER_SIZE 256

// define del assert_pe macro
#define ASSERT_PE(t,c,e) {\
                          const struct parser_event *res= e;\
                          assert(1 == res->n);\
                          assert(t == res->type);\
                          assert(c == res->data[0]);\
                        }

// test functions
void test_num_ok(void);
void test_num_inv(void);
void test_crlf_ok(void);
void test_http_ok(void);
void test_te_ok(void);
void test_te_inv(void);
void test_cl_ok(void);
void test_cl_inv(void);
void test_ct_ok(void);
void test_ct_inv(void);
void test_doh_ok(void);

int
main(void) {
  test_num_ok();
  test_num_inv();
  test_crlf_ok();
  test_http_ok();
  test_te_ok();
  test_te_inv();
  test_cl_ok();
  test_cl_inv();
  test_ct_ok();
  test_ct_inv();
  test_doh_ok();
  return 0;
}

void test_num_ok(void){

  struct parser_definition d = get_parser_num_definition();

  struct parser *parser = parser_init(parser_no_classes(), &d);

  struct buffer message;
  buffer *m = &message;
  uint8_t direct_buff_m[TEST_BUFFER_SIZE];
  buffer_init(&message, N(direct_buff_m), direct_buff_m);

  buffer_write_string(m,"12345\r\n");

  ASSERT_PE(NUMS_EVENT_OK, '1', parser_feed(parser,buffer_read(m)));
  ASSERT_PE(NUMS_EVENT_OK, '2', parser_feed(parser,buffer_read(m)));
  ASSERT_PE(NUMS_EVENT_OK, '3', parser_feed(parser,buffer_read(m)));
  ASSERT_PE(NUMS_EVENT_OK, '4', parser_feed(parser,buffer_read(m)));
  ASSERT_PE(NUMS_EVENT_OK, '5', parser_feed(parser,buffer_read(m)));
  ASSERT_PE(NUMS_EVENT_END, '\r', parser_feed(parser,buffer_read(m)));
  ASSERT_PE(NUMS_EVENT_END, '\n', parser_feed(parser,buffer_read(m)));

  parser_destroy(parser);
  printf("parser_test/num_ok:\tsuccess!\n");
  return;
}

void test_num_inv(void){
  struct parser_definition d = get_parser_num_definition();

  struct parser *parser = parser_init(parser_no_classes(), &d);

  struct buffer message;
  buffer *m = &message;
  uint8_t direct_buff_m[TEST_BUFFER_SIZE];
  buffer_init(&message, N(direct_buff_m), direct_buff_m);

  buffer_write_string(m,"12j45\r\n");


  ASSERT_PE(NUMS_EVENT_OK, '1', parser_feed(parser,buffer_read(m)));
  ASSERT_PE(NUMS_EVENT_OK, '2', parser_feed(parser,buffer_read(m)));
  ASSERT_PE(NUMS_EVENT_END, 'j', parser_feed(parser,buffer_read(m)));
  ASSERT_PE(NUMS_EVENT_END, '4', parser_feed(parser,buffer_read(m)));
  ASSERT_PE(NUMS_EVENT_END, '5', parser_feed(parser,buffer_read(m)));
  ASSERT_PE(NUMS_EVENT_END, '\r', parser_feed(parser,buffer_read(m)));
  ASSERT_PE(NUMS_EVENT_END, '\n', parser_feed(parser,buffer_read(m)));

  parser_destroy(parser);
  printf("parser_test/num_inv:\tsuccess!\n");
  return;
}

void test_crlf_ok(void){

  struct parser_definition d = get_parser_crlf_definition();

  struct parser *parser = parser_init(parser_no_classes(), &d);

  struct buffer message;
  buffer *m = &message;
  uint8_t direct_buff_m[TEST_BUFFER_SIZE];
  buffer_init(&message, N(direct_buff_m), direct_buff_m);

  buffer_write_string(m,"hey\rhey\r\nhey\r\n\r\nhey\r\n");


  ASSERT_PE(HTTP_S_EVENT_NOTHING, 'h', parser_feed(parser,buffer_read(m)));
  ASSERT_PE(HTTP_S_EVENT_NOTHING, 'e', parser_feed(parser,buffer_read(m)));
  ASSERT_PE(HTTP_S_EVENT_NOTHING, 'y', parser_feed(parser,buffer_read(m)));
  ASSERT_PE(HTTP_S_EVENT_NOTHING, '\r', parser_feed(parser,buffer_read(m)));
  ASSERT_PE(HTTP_S_EVENT_NOTHING, 'h', parser_feed(parser,buffer_read(m)));
  ASSERT_PE(HTTP_S_EVENT_NOTHING, 'e', parser_feed(parser,buffer_read(m)));
  ASSERT_PE(HTTP_S_EVENT_NOTHING, 'y', parser_feed(parser,buffer_read(m)));
  ASSERT_PE(HTTP_S_EVENT_NOTHING, '\r', parser_feed(parser,buffer_read(m)));
  ASSERT_PE(HTTP_S_EVENT_CRLF, '\n', parser_feed(parser,buffer_read(m)));
  ASSERT_PE(HTTP_S_EVENT_NOTHING, 'h', parser_feed(parser,buffer_read(m)));
  ASSERT_PE(HTTP_S_EVENT_NOTHING, 'e', parser_feed(parser,buffer_read(m)));
  ASSERT_PE(HTTP_S_EVENT_NOTHING, 'y', parser_feed(parser,buffer_read(m)));
  ASSERT_PE(HTTP_S_EVENT_NOTHING, '\r', parser_feed(parser,buffer_read(m)));
  ASSERT_PE(HTTP_S_EVENT_CRLF, '\n', parser_feed(parser,buffer_read(m)));
  ASSERT_PE(HTTP_S_EVENT_NOTHING, '\r', parser_feed(parser,buffer_read(m)));
  ASSERT_PE(HTTP_S_EVENT_END, '\n', parser_feed(parser,buffer_read(m)));
  ASSERT_PE(HTTP_S_EVENT_END, 'h', parser_feed(parser,buffer_read(m)));
  ASSERT_PE(HTTP_S_EVENT_END, 'e', parser_feed(parser,buffer_read(m)));
  ASSERT_PE(HTTP_S_EVENT_END, 'y', parser_feed(parser,buffer_read(m)));
  ASSERT_PE(HTTP_S_EVENT_END, '\r', parser_feed(parser,buffer_read(m)));
  ASSERT_PE(HTTP_S_EVENT_END, '\n', parser_feed(parser,buffer_read(m)));

  parser_destroy(parser);
  printf("parser_test/crlf_ok:\tsuccess!\n");
  return;
}

void test_http_ok(void){

  struct parser_definition d = get_parser_http_definition();

  struct parser *parser = parser_init(parser_no_classes(), &d);

  struct buffer message;
  buffer *m = &message;
  uint8_t direct_buff_m[TEST_BUFFER_SIZE];
  buffer_init(&message, N(direct_buff_m), direct_buff_m);

  buffer_write_string(m,"http/1.1 200\rOK\r\n\r\n");


  ASSERT_PE(HTTP_S_EVENT_NOTHING, 'h', parser_feed(parser,buffer_read(m)));
  ASSERT_PE(HTTP_S_EVENT_NOTHING, 't', parser_feed(parser,buffer_read(m)));
  ASSERT_PE(HTTP_S_EVENT_NOTHING, 't', parser_feed(parser,buffer_read(m)));
  ASSERT_PE(HTTP_S_EVENT_NOTHING, 'p', parser_feed(parser,buffer_read(m)));
  ASSERT_PE(HTTP_S_EVENT_NOTHING, '/', parser_feed(parser,buffer_read(m)));
  ASSERT_PE(HTTP_S_EVENT_NOTHING, '1', parser_feed(parser,buffer_read(m)));
  ASSERT_PE(HTTP_S_EVENT_NOTHING, '.', parser_feed(parser,buffer_read(m)));
  ASSERT_PE(HTTP_S_EVENT_NOTHING, '1', parser_feed(parser,buffer_read(m)));
  ASSERT_PE(HTTP_S_EVENT_NOTHING, ' ', parser_feed(parser,buffer_read(m)));
  ASSERT_PE(HTTP_S_EVENT_PARSING_CODE, '2', parser_feed(parser,buffer_read(m)));
  ASSERT_PE(HTTP_S_EVENT_PARSING_CODE, '0', parser_feed(parser,buffer_read(m)));
  ASSERT_PE(HTTP_S_EVENT_PARSING_CODE, '0', parser_feed(parser,buffer_read(m)));
  ASSERT_PE(HTTP_S_EVENT_PARSED_CODE, '\r', parser_feed(parser,buffer_read(m)));
  ASSERT_PE(HTTP_S_EVENT_NOTHING, 'O', parser_feed(parser,buffer_read(m)));
  ASSERT_PE(HTTP_S_EVENT_NOTHING, 'K', parser_feed(parser,buffer_read(m)));
  ASSERT_PE(HTTP_S_EVENT_NOTHING, '\r', parser_feed(parser,buffer_read(m)));
  ASSERT_PE(HTTP_S_EVENT_CRLF, '\n', parser_feed(parser,buffer_read(m)));
  ASSERT_PE(HTTP_S_EVENT_NOTHING, '\r', parser_feed(parser,buffer_read(m)));
  ASSERT_PE(HTTP_S_EVENT_END, '\n', parser_feed(parser,buffer_read(m)));

  parser_destroy(parser);
  printf("parser_test/http_ok:\tsuccess!\n");
  return;
}

void test_te_ok(void){

  struct parser_definition d = get_parser_te_definition();

  struct parser *parser = parser_init(parser_no_classes(), &d);

  struct buffer message;
  buffer *m = &message;
  uint8_t direct_buff_m[TEST_BUFFER_SIZE];
  buffer_init(&message, N(direct_buff_m), direct_buff_m);

  char* str = "Transfer-Encoding: chunked\r\n";
  buffer_write_string(m,str);

  ASSERT_PE(STRING_CMP_MAYEQ, 'T', parser_feed(parser,buffer_read(m)));
  ASSERT_PE(STRING_CMP_MAYEQ, 'r', parser_feed(parser,buffer_read(m)));
  ASSERT_PE(STRING_CMP_MAYEQ, 'a', parser_feed(parser,buffer_read(m)));
  ASSERT_PE(STRING_CMP_MAYEQ, 'n', parser_feed(parser,buffer_read(m)));
  ASSERT_PE(STRING_CMP_MAYEQ, 's', parser_feed(parser,buffer_read(m)));
  ASSERT_PE(STRING_CMP_MAYEQ, 'f', parser_feed(parser,buffer_read(m)));
  ASSERT_PE(STRING_CMP_MAYEQ, 'e', parser_feed(parser,buffer_read(m)));
  ASSERT_PE(STRING_CMP_MAYEQ, 'r', parser_feed(parser,buffer_read(m)));
  ASSERT_PE(STRING_CMP_MAYEQ, '-', parser_feed(parser,buffer_read(m)));
  ASSERT_PE(STRING_CMP_MAYEQ, 'E', parser_feed(parser,buffer_read(m)));
  ASSERT_PE(STRING_CMP_MAYEQ, 'n', parser_feed(parser,buffer_read(m)));
  ASSERT_PE(STRING_CMP_MAYEQ, 'c', parser_feed(parser,buffer_read(m)));
  ASSERT_PE(STRING_CMP_MAYEQ, 'o', parser_feed(parser,buffer_read(m)));
  ASSERT_PE(STRING_CMP_MAYEQ, 'd', parser_feed(parser,buffer_read(m)));
  ASSERT_PE(STRING_CMP_MAYEQ, 'i', parser_feed(parser,buffer_read(m)));
  ASSERT_PE(STRING_CMP_MAYEQ, 'n', parser_feed(parser,buffer_read(m)));
  ASSERT_PE(STRING_CMP_MAYEQ, 'g', parser_feed(parser,buffer_read(m)));
  ASSERT_PE(STRING_CMP_MAYEQ, ':', parser_feed(parser,buffer_read(m)));
  ASSERT_PE(STRING_CMP_MAYEQ, ' ', parser_feed(parser,buffer_read(m)));
  ASSERT_PE(STRING_CMP_MAYEQ, 'c', parser_feed(parser,buffer_read(m)));
  ASSERT_PE(STRING_CMP_MAYEQ, 'h', parser_feed(parser,buffer_read(m)));
  ASSERT_PE(STRING_CMP_MAYEQ, 'u', parser_feed(parser,buffer_read(m)));
  ASSERT_PE(STRING_CMP_MAYEQ, 'n', parser_feed(parser,buffer_read(m)));
  ASSERT_PE(STRING_CMP_MAYEQ, 'k', parser_feed(parser,buffer_read(m)));
  ASSERT_PE(STRING_CMP_MAYEQ, 'e', parser_feed(parser,buffer_read(m)));
  ASSERT_PE(STRING_CMP_EQ, 'd', parser_feed(parser,buffer_read(m)));
  ASSERT_PE(STRING_CMP_NEQ, '\r', parser_feed(parser,buffer_read(m)));
  ASSERT_PE(STRING_CMP_NEQ, '\n', parser_feed(parser,buffer_read(m)));

  parser_destroy(parser);
  parser_utils_strcmpi_destroy(&d);
  printf("parser_test/te_ok:\tsuccess!\n");
  return;
}

void test_te_inv(void){

  struct parser_definition d = get_parser_te_definition();

  struct parser *parser = parser_init(parser_no_classes(), &d);

  struct buffer message;
  buffer *m = &message;
  uint8_t direct_buff_m[TEST_BUFFER_SIZE];
  buffer_init(&message, N(direct_buff_m), direct_buff_m);

  char* str = "Transfer-Encoding: deflated\r\n";
  buffer_write_string(m,str);

  ASSERT_PE(STRING_CMP_MAYEQ, 'T', parser_feed(parser,buffer_read(m)));
  ASSERT_PE(STRING_CMP_MAYEQ, 'r', parser_feed(parser,buffer_read(m)));
  ASSERT_PE(STRING_CMP_MAYEQ, 'a', parser_feed(parser,buffer_read(m)));
  ASSERT_PE(STRING_CMP_MAYEQ, 'n', parser_feed(parser,buffer_read(m)));
  ASSERT_PE(STRING_CMP_MAYEQ, 's', parser_feed(parser,buffer_read(m)));
  ASSERT_PE(STRING_CMP_MAYEQ, 'f', parser_feed(parser,buffer_read(m)));
  ASSERT_PE(STRING_CMP_MAYEQ, 'e', parser_feed(parser,buffer_read(m)));
  ASSERT_PE(STRING_CMP_MAYEQ, 'r', parser_feed(parser,buffer_read(m)));
  ASSERT_PE(STRING_CMP_MAYEQ, '-', parser_feed(parser,buffer_read(m)));
  ASSERT_PE(STRING_CMP_MAYEQ, 'E', parser_feed(parser,buffer_read(m)));
  ASSERT_PE(STRING_CMP_MAYEQ, 'n', parser_feed(parser,buffer_read(m)));
  ASSERT_PE(STRING_CMP_MAYEQ, 'c', parser_feed(parser,buffer_read(m)));
  ASSERT_PE(STRING_CMP_MAYEQ, 'o', parser_feed(parser,buffer_read(m)));
  ASSERT_PE(STRING_CMP_MAYEQ, 'd', parser_feed(parser,buffer_read(m)));
  ASSERT_PE(STRING_CMP_MAYEQ, 'i', parser_feed(parser,buffer_read(m)));
  ASSERT_PE(STRING_CMP_MAYEQ, 'n', parser_feed(parser,buffer_read(m)));
  ASSERT_PE(STRING_CMP_MAYEQ, 'g', parser_feed(parser,buffer_read(m)));
  ASSERT_PE(STRING_CMP_MAYEQ, ':', parser_feed(parser,buffer_read(m)));
  ASSERT_PE(STRING_CMP_MAYEQ, ' ', parser_feed(parser,buffer_read(m)));
  ASSERT_PE(STRING_CMP_NEQ, 'd', parser_feed(parser,buffer_read(m)));
  ASSERT_PE(STRING_CMP_NEQ, 'e', parser_feed(parser,buffer_read(m)));
  ASSERT_PE(STRING_CMP_NEQ, 'f', parser_feed(parser,buffer_read(m)));
  ASSERT_PE(STRING_CMP_NEQ, 'l', parser_feed(parser,buffer_read(m)));
  ASSERT_PE(STRING_CMP_NEQ, 'a', parser_feed(parser,buffer_read(m)));
  ASSERT_PE(STRING_CMP_NEQ, 't', parser_feed(parser,buffer_read(m)));
  ASSERT_PE(STRING_CMP_NEQ, 'e', parser_feed(parser,buffer_read(m)));
  ASSERT_PE(STRING_CMP_NEQ, 'd', parser_feed(parser,buffer_read(m)));
  ASSERT_PE(STRING_CMP_NEQ, '\r', parser_feed(parser,buffer_read(m)));
  ASSERT_PE(STRING_CMP_NEQ, '\n', parser_feed(parser,buffer_read(m)));

  parser_destroy(parser);
  parser_utils_strcmpi_destroy(&d);
  printf("parser_test/te_inv:\tsuccess!\n");
  return;
}

void test_cl_ok(void){

  struct parser_definition d = get_parser_cl_definition();

  struct parser *parser = parser_init(parser_no_classes(), &d);

  struct buffer message;
  buffer *m = &message;
  uint8_t direct_buff_m[TEST_BUFFER_SIZE];
  buffer_init(&message, N(direct_buff_m), direct_buff_m);

  char* str = "Content-Length: \r\n";
  buffer_write_string(m,str);

  ASSERT_PE(STRING_CMP_MAYEQ, 'C', parser_feed(parser,buffer_read(m)));
  ASSERT_PE(STRING_CMP_MAYEQ, 'o', parser_feed(parser,buffer_read(m)));
  ASSERT_PE(STRING_CMP_MAYEQ, 'n', parser_feed(parser,buffer_read(m)));
  ASSERT_PE(STRING_CMP_MAYEQ, 't', parser_feed(parser,buffer_read(m)));
  ASSERT_PE(STRING_CMP_MAYEQ, 'e', parser_feed(parser,buffer_read(m)));
  ASSERT_PE(STRING_CMP_MAYEQ, 'n', parser_feed(parser,buffer_read(m)));
  ASSERT_PE(STRING_CMP_MAYEQ, 't', parser_feed(parser,buffer_read(m)));
  ASSERT_PE(STRING_CMP_MAYEQ, '-', parser_feed(parser,buffer_read(m)));
  ASSERT_PE(STRING_CMP_MAYEQ, 'L', parser_feed(parser,buffer_read(m)));
  ASSERT_PE(STRING_CMP_MAYEQ, 'e', parser_feed(parser,buffer_read(m)));
  ASSERT_PE(STRING_CMP_MAYEQ, 'n', parser_feed(parser,buffer_read(m)));
  ASSERT_PE(STRING_CMP_MAYEQ, 'g', parser_feed(parser,buffer_read(m)));
  ASSERT_PE(STRING_CMP_MAYEQ, 't', parser_feed(parser,buffer_read(m)));
  ASSERT_PE(STRING_CMP_MAYEQ, 'h', parser_feed(parser,buffer_read(m)));
  ASSERT_PE(STRING_CMP_MAYEQ, ':', parser_feed(parser,buffer_read(m)));
  ASSERT_PE(STRING_CMP_EQ, ' ', parser_feed(parser,buffer_read(m)));
  ASSERT_PE(STRING_CMP_NEQ, '\r', parser_feed(parser,buffer_read(m)));
  ASSERT_PE(STRING_CMP_NEQ, '\n', parser_feed(parser,buffer_read(m)));

  parser_destroy(parser);
  parser_utils_strcmpi_destroy(&d);
  printf("parser_test/cl_ok:\tsuccess!\n");
  return;
}

void test_cl_inv(void){

  struct parser_definition d = get_parser_cl_definition();

  struct parser *parser = parser_init(parser_no_classes(), &d);

  struct buffer message;
  buffer *m = &message;
  uint8_t direct_buff_m[TEST_BUFFER_SIZE];
  buffer_init(&message, N(direct_buff_m), direct_buff_m);

  char* str = "Contest-Length: \r\n";
  buffer_write_string(m,str);

  ASSERT_PE(STRING_CMP_MAYEQ, 'C', parser_feed(parser,buffer_read(m)));
  ASSERT_PE(STRING_CMP_MAYEQ, 'o', parser_feed(parser,buffer_read(m)));
  ASSERT_PE(STRING_CMP_MAYEQ, 'n', parser_feed(parser,buffer_read(m)));
  ASSERT_PE(STRING_CMP_MAYEQ, 't', parser_feed(parser,buffer_read(m)));
  ASSERT_PE(STRING_CMP_MAYEQ, 'e', parser_feed(parser,buffer_read(m)));
  ASSERT_PE(STRING_CMP_NEQ, 's', parser_feed(parser,buffer_read(m)));
  ASSERT_PE(STRING_CMP_NEQ, 't', parser_feed(parser,buffer_read(m)));
  ASSERT_PE(STRING_CMP_NEQ, '-', parser_feed(parser,buffer_read(m)));
  ASSERT_PE(STRING_CMP_NEQ, 'L', parser_feed(parser,buffer_read(m)));
  ASSERT_PE(STRING_CMP_NEQ, 'e', parser_feed(parser,buffer_read(m)));
  ASSERT_PE(STRING_CMP_NEQ, 'n', parser_feed(parser,buffer_read(m)));
  ASSERT_PE(STRING_CMP_NEQ, 'g', parser_feed(parser,buffer_read(m)));
  ASSERT_PE(STRING_CMP_NEQ, 't', parser_feed(parser,buffer_read(m)));
  ASSERT_PE(STRING_CMP_NEQ, 'h', parser_feed(parser,buffer_read(m)));
  ASSERT_PE(STRING_CMP_NEQ, ':', parser_feed(parser,buffer_read(m)));
  ASSERT_PE(STRING_CMP_NEQ, ' ', parser_feed(parser,buffer_read(m)));
  ASSERT_PE(STRING_CMP_NEQ, '\r', parser_feed(parser,buffer_read(m)));
  ASSERT_PE(STRING_CMP_NEQ, '\n', parser_feed(parser,buffer_read(m)));

  parser_destroy(parser);
  parser_utils_strcmpi_destroy(&d);
  printf("parser_test/cl_inv:\tsuccess!\n");
  return;
}

void test_ct_ok(void){

  struct parser_definition d = get_parser_ct_definition();

  struct parser *parser = parser_init(parser_no_classes(), &d);

  struct buffer message;
  buffer *m = &message;
  uint8_t direct_buff_m[TEST_BUFFER_SIZE];
  buffer_init(&message, N(direct_buff_m), direct_buff_m);

  char* str = "Content-Type: application/dns-message\r\n";
  buffer_write_string(m,str);

  ASSERT_PE(STRING_CMP_MAYEQ, 'C', parser_feed(parser,buffer_read(m)));
  ASSERT_PE(STRING_CMP_MAYEQ, 'o', parser_feed(parser,buffer_read(m)));
  ASSERT_PE(STRING_CMP_MAYEQ, 'n', parser_feed(parser,buffer_read(m)));
  ASSERT_PE(STRING_CMP_MAYEQ, 't', parser_feed(parser,buffer_read(m)));
  ASSERT_PE(STRING_CMP_MAYEQ, 'e', parser_feed(parser,buffer_read(m)));
  ASSERT_PE(STRING_CMP_MAYEQ, 'n', parser_feed(parser,buffer_read(m)));
  ASSERT_PE(STRING_CMP_MAYEQ, 't', parser_feed(parser,buffer_read(m)));
  ASSERT_PE(STRING_CMP_MAYEQ, '-', parser_feed(parser,buffer_read(m)));
  ASSERT_PE(STRING_CMP_MAYEQ, 'T', parser_feed(parser,buffer_read(m)));
  ASSERT_PE(STRING_CMP_MAYEQ, 'y', parser_feed(parser,buffer_read(m)));
  ASSERT_PE(STRING_CMP_MAYEQ, 'p', parser_feed(parser,buffer_read(m)));
  ASSERT_PE(STRING_CMP_MAYEQ, 'e', parser_feed(parser,buffer_read(m)));
  ASSERT_PE(STRING_CMP_MAYEQ, ':', parser_feed(parser,buffer_read(m)));
  ASSERT_PE(STRING_CMP_MAYEQ, ' ', parser_feed(parser,buffer_read(m)));
  ASSERT_PE(STRING_CMP_MAYEQ, 'a', parser_feed(parser,buffer_read(m)));
  ASSERT_PE(STRING_CMP_MAYEQ, 'p', parser_feed(parser,buffer_read(m)));
  ASSERT_PE(STRING_CMP_MAYEQ, 'p', parser_feed(parser,buffer_read(m)));
  ASSERT_PE(STRING_CMP_MAYEQ, 'l', parser_feed(parser,buffer_read(m)));
  ASSERT_PE(STRING_CMP_MAYEQ, 'i', parser_feed(parser,buffer_read(m)));
  ASSERT_PE(STRING_CMP_MAYEQ, 'c', parser_feed(parser,buffer_read(m)));
  ASSERT_PE(STRING_CMP_MAYEQ, 'a', parser_feed(parser,buffer_read(m)));
  ASSERT_PE(STRING_CMP_MAYEQ, 't', parser_feed(parser,buffer_read(m)));
  ASSERT_PE(STRING_CMP_MAYEQ, 'i', parser_feed(parser,buffer_read(m)));
  ASSERT_PE(STRING_CMP_MAYEQ, 'o', parser_feed(parser,buffer_read(m)));
  ASSERT_PE(STRING_CMP_MAYEQ, 'n', parser_feed(parser,buffer_read(m)));
  ASSERT_PE(STRING_CMP_MAYEQ, '/', parser_feed(parser,buffer_read(m)));
  ASSERT_PE(STRING_CMP_MAYEQ, 'd', parser_feed(parser,buffer_read(m)));
  ASSERT_PE(STRING_CMP_MAYEQ, 'n', parser_feed(parser,buffer_read(m)));
  ASSERT_PE(STRING_CMP_MAYEQ, 's', parser_feed(parser,buffer_read(m)));
  ASSERT_PE(STRING_CMP_MAYEQ, '-', parser_feed(parser,buffer_read(m)));
  ASSERT_PE(STRING_CMP_MAYEQ, 'm', parser_feed(parser,buffer_read(m)));
  ASSERT_PE(STRING_CMP_MAYEQ, 'e', parser_feed(parser,buffer_read(m)));
  ASSERT_PE(STRING_CMP_MAYEQ, 's', parser_feed(parser,buffer_read(m)));
  ASSERT_PE(STRING_CMP_MAYEQ, 's', parser_feed(parser,buffer_read(m)));
  ASSERT_PE(STRING_CMP_MAYEQ, 'a', parser_feed(parser,buffer_read(m)));
  ASSERT_PE(STRING_CMP_MAYEQ, 'g', parser_feed(parser,buffer_read(m)));
  ASSERT_PE(STRING_CMP_EQ, 'e', parser_feed(parser,buffer_read(m)));
  ASSERT_PE(STRING_CMP_NEQ, '\r', parser_feed(parser,buffer_read(m)));
  ASSERT_PE(STRING_CMP_NEQ, '\n', parser_feed(parser,buffer_read(m)));

  parser_destroy(parser);
  parser_utils_strcmpi_destroy(&d);
  printf("parser_test/ct_ok:success!\n");
  return;
}

void test_ct_inv(void){

  struct parser_definition d = get_parser_ct_definition();

  struct parser *parser = parser_init(parser_no_classes(), &d);

  struct buffer message;
  buffer *m = &message;
  uint8_t direct_buff_m[TEST_BUFFER_SIZE];
  buffer_init(&message, N(direct_buff_m), direct_buff_m);

  char* str = "Content-Type: application/html\r\n";
  buffer_write_string(m,str);

  ASSERT_PE(STRING_CMP_MAYEQ, 'C', parser_feed(parser,buffer_read(m)));
  ASSERT_PE(STRING_CMP_MAYEQ, 'o', parser_feed(parser,buffer_read(m)));
  ASSERT_PE(STRING_CMP_MAYEQ, 'n', parser_feed(parser,buffer_read(m)));
  ASSERT_PE(STRING_CMP_MAYEQ, 't', parser_feed(parser,buffer_read(m)));
  ASSERT_PE(STRING_CMP_MAYEQ, 'e', parser_feed(parser,buffer_read(m)));
  ASSERT_PE(STRING_CMP_MAYEQ, 'n', parser_feed(parser,buffer_read(m)));
  ASSERT_PE(STRING_CMP_MAYEQ, 't', parser_feed(parser,buffer_read(m)));
  ASSERT_PE(STRING_CMP_MAYEQ, '-', parser_feed(parser,buffer_read(m)));
  ASSERT_PE(STRING_CMP_MAYEQ, 'T', parser_feed(parser,buffer_read(m)));
  ASSERT_PE(STRING_CMP_MAYEQ, 'y', parser_feed(parser,buffer_read(m)));
  ASSERT_PE(STRING_CMP_MAYEQ, 'p', parser_feed(parser,buffer_read(m)));
  ASSERT_PE(STRING_CMP_MAYEQ, 'e', parser_feed(parser,buffer_read(m)));
  ASSERT_PE(STRING_CMP_MAYEQ, ':', parser_feed(parser,buffer_read(m)));
  ASSERT_PE(STRING_CMP_MAYEQ, ' ', parser_feed(parser,buffer_read(m)));
  ASSERT_PE(STRING_CMP_MAYEQ, 'a', parser_feed(parser,buffer_read(m)));
  ASSERT_PE(STRING_CMP_MAYEQ, 'p', parser_feed(parser,buffer_read(m)));
  ASSERT_PE(STRING_CMP_MAYEQ, 'p', parser_feed(parser,buffer_read(m)));
  ASSERT_PE(STRING_CMP_MAYEQ, 'l', parser_feed(parser,buffer_read(m)));
  ASSERT_PE(STRING_CMP_MAYEQ, 'i', parser_feed(parser,buffer_read(m)));
  ASSERT_PE(STRING_CMP_MAYEQ, 'c', parser_feed(parser,buffer_read(m)));
  ASSERT_PE(STRING_CMP_MAYEQ, 'a', parser_feed(parser,buffer_read(m)));
  ASSERT_PE(STRING_CMP_MAYEQ, 't', parser_feed(parser,buffer_read(m)));
  ASSERT_PE(STRING_CMP_MAYEQ, 'i', parser_feed(parser,buffer_read(m)));
  ASSERT_PE(STRING_CMP_MAYEQ, 'o', parser_feed(parser,buffer_read(m)));
  ASSERT_PE(STRING_CMP_MAYEQ, 'n', parser_feed(parser,buffer_read(m)));
  ASSERT_PE(STRING_CMP_MAYEQ, '/', parser_feed(parser,buffer_read(m)));
  ASSERT_PE(STRING_CMP_NEQ, 'h', parser_feed(parser,buffer_read(m)));
  ASSERT_PE(STRING_CMP_NEQ, 't', parser_feed(parser,buffer_read(m)));
  ASSERT_PE(STRING_CMP_NEQ, 'm', parser_feed(parser,buffer_read(m)));
  ASSERT_PE(STRING_CMP_NEQ, 'l', parser_feed(parser,buffer_read(m)));
  ASSERT_PE(STRING_CMP_NEQ, '\r', parser_feed(parser,buffer_read(m)));
  ASSERT_PE(STRING_CMP_NEQ, '\n', parser_feed(parser,buffer_read(m)));

  parser_destroy(parser);
  parser_utils_strcmpi_destroy(&d);
  printf("parser_test/ct_inv:\tsuccess!\n");
  return;
}

void test_doh_ok(void){

  struct parser_doh *parser = parser_doh_init();

  struct buffer message;
  buffer *m = &message;
  uint8_t direct_buff_m[TEST_BUFFER_SIZE];
  buffer_init(&message, N(direct_buff_m), direct_buff_m);

  buffer_write_string(m,"http/1.1 200 \rOK\r\nContent-Type: application/dns-message\r\n");

  while(buffer_can_read(m)){
    parser_doh_feed(parser,buffer_read(m));
  }

  assert(parser_doh_getStatusCode(parser) == 200);
  assert(parser_doh_isValidContentType(parser) == 1);

  parser_doh_destroy(parser);
  printf("parser_test/doh_ok:\tsuccess!\n");
  return;
}
