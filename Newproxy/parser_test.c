#include <stdio.h>
#include <stdlib.h>
#include <assert.h>
#include <errno.h>
#include <string.h>
#include <sys/types.h>

#include "buffer.h"
#include "parser.h"
#include "parser_num.h"
#include "parser_doh.h"
#include "parser_crlf.h"

// test functions
void test_num_ok(void);
void test_num_invalid(void);
void test_crlf_ok(void);

static void
assert_eq(const unsigned type, const int c, const struct parser_event *e) {
    printf("input: %c, expect %d, got %d\n",c,(int)type,(int)e->type);
    assert(1 == e->n);
    assert(type == e->type);
    assert(c == e->data[0]);

    return;
}

int
main(void) {
  test_num_ok();
  test_num_invalid();
  test_crlf_ok();
  return 0;
}

void test_num_ok(void){

  struct parser_definition d = get_parser_num_definition();

  struct parser *parser = parser_init(parser_no_classes(), &d);

  assert_eq(NUMS_EVENT_OK, '1', parser_feed(parser,'1'));
  assert_eq(NUMS_EVENT_OK, '2', parser_feed(parser,'2'));
  assert_eq(NUMS_EVENT_OK, '3', parser_feed(parser,'3'));
  assert_eq(NUMS_EVENT_OK, '4', parser_feed(parser,'4'));
  assert_eq(NUMS_EVENT_OK, '5', parser_feed(parser,'5'));
  assert_eq(NUMS_EVENT_END, '\r', parser_feed(parser,'\r'));
  assert_eq(NUMS_EVENT_END, '\n', parser_feed(parser,'\n'));

  parser_destroy(parser);
  printf("parser_test/num_ok: success!\n");
  return;
}

void test_num_invalid(void){
  struct parser_definition d = get_parser_num_definition();

  struct parser *parser = parser_init(parser_no_classes(), &d);

  assert_eq(NUMS_EVENT_OK, '1', parser_feed(parser,'1'));
  assert_eq(NUMS_EVENT_OK, '2', parser_feed(parser,'2'));
  assert_eq(NUMS_EVENT_ERROR, 'j', parser_feed(parser,'j'));
  assert_eq(NUMS_EVENT_ERROR, '4', parser_feed(parser,'4'));
  assert_eq(NUMS_EVENT_ERROR, '5', parser_feed(parser,'5'));
  assert_eq(NUMS_EVENT_ERROR, '\r', parser_feed(parser,'\r'));
  assert_eq(NUMS_EVENT_ERROR, '\n', parser_feed(parser,'\n'));

  parser_destroy(parser);
  printf("parser_test/num_invalid: success!\n");
  return;
}

void test_crlf_ok(void){

  struct parser_definition d = get_parser_crlf_definition();

  struct parser *parser = parser_init(parser_no_classes(), &d);

  assert_eq(CRLF_S_EVENT_NOTHING, 'h', parser_feed(parser,'h'));
  assert_eq(CRLF_S_EVENT_NOTHING, 'e', parser_feed(parser,'e'));
  assert_eq(CRLF_S_EVENT_NOTHING, 'y', parser_feed(parser,'y'));
  assert_eq(CRLF_S_EVENT_NOTHING, '\r', parser_feed(parser,'\r'));
  assert_eq(CRLF_S_EVENT_NOTHING, 'h', parser_feed(parser,'h'));
  assert_eq(CRLF_S_EVENT_NOTHING, 'e', parser_feed(parser,'e'));
  assert_eq(CRLF_S_EVENT_NOTHING, 'y', parser_feed(parser,'y'));
  assert_eq(CRLF_S_EVENT_NOTHING, '\r', parser_feed(parser,'\r'));
  assert_eq(CRLF_S_EVENT_CRLF, '\n', parser_feed(parser,'\n'));
  assert_eq(CRLF_S_EVENT_NOTHING, 'h', parser_feed(parser,'h'));
  assert_eq(CRLF_S_EVENT_NOTHING, 'e', parser_feed(parser,'e'));
  assert_eq(CRLF_S_EVENT_NOTHING, 'y', parser_feed(parser,'y'));
  assert_eq(CRLF_S_EVENT_NOTHING, '\r', parser_feed(parser,'\r'));
  assert_eq(CRLF_S_EVENT_CRLF, '\n', parser_feed(parser,'\n'));
  assert_eq(CRLF_S_EVENT_NOTHING, '\r', parser_feed(parser,'\r'));
  assert_eq(CRLF_S_EVENT_END, '\n', parser_feed(parser,'\n'));
  assert_eq(CRLF_S_EVENT_END, 'h', parser_feed(parser,'h'));
  assert_eq(CRLF_S_EVENT_END, 'e', parser_feed(parser,'e'));
  assert_eq(CRLF_S_EVENT_END, 'y', parser_feed(parser,'y'));
  assert_eq(CRLF_S_EVENT_END, '\r', parser_feed(parser,'\r'));
  assert_eq(CRLF_S_EVENT_END, '\n', parser_feed(parser,'\n'));

  parser_destroy(parser);
  printf("parser_test/crlf_ok: success!\n");
  return;
}
