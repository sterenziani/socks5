##
# Makefile para proxy SOCKS5
##

# Variables para compilador C
CC=clang
CCFLAGS=-pthread -g --std=c11 -pedantic -pedantic-errors -Wall -Wextra -Werror -Wno-unused-parameter -Wno-implicit-fallthrough -D_POSIX_C_SOURCE=200112L
DIR=Proxy
DOH_DIR=$(DIR)/DOH
TEST_DIR=Tests
TEST_C=$(wildcard $(TEST_DIR)/*.c)
DEPS=$(DIR)/buffer.h $(DIR)/parser.h $(DIR)/parser_utils.h $(DOH_DIR)/doh.h $(DOH_DIR)/parser_num.h $(DOH_DIR)/parser_http.h $(DOH_DIR)/parser_doh.h
OBJ=$(DEPS:.h=.o)

# Variables para doh Server
## Al modificar el puerto, recordar tambien modificar dicho valor en Proxy/doh.c
DOCKER=sudo docker
DOH_PORT=8053
DOH_IMAGE=doh-nginx
DOH_CONTAINER=doh-server

.PHONY: doh-build
doh-build:
	$(DOCKER) pull nginx
	$(DOCKER) build -t $(DOH_IMAGE) ./doh_server/

.PHONY: doh-stop
doh-stop:
	$(DOCKER) stop $(DOH_CONTAINER) | true
	$(DOCKER) rm -f $(DOH_CONTAINER) | true

.PHONY: doh-start
doh-start: doh-stop
	$(DOCKER) run --name $(DOH_CONTAINER) -d -p $(DOH_PORT):80 $(DOH_IMAGE)

%.o: %.c $(DEPS)
	$(CC) -c -o $@ $< $(CCFLAGS)

# Tests
$(TEST_DIR)/%_test: $(OBJ)
	$(CC) -c -o $@.o $(CCFLAGS) $@.c
	$(CC) -o $@ $^ $@.o $(CCFLAGS)
	rm -rf $@.o

.PHONY: tests
tests: $(subst .c,,$(TEST_C))
	$(subst .c,; ,$(TEST_C))

.PHONY: clean
clean:
	rm -rf $(DIR)/*.o $(DIR)/*.out $(DIR)/*.dSYM *.o *.bin *.out $(TEST_DIR)/*_test
