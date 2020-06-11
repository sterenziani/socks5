##
# Makefile para proxy SOCKS5
##

# Variables para compilador C
CC=gcc
CCFLAGS=-pthread -g --std=c11 -pedantic -pedantic-errors -Wall -Wextra -Werror -Wno-unused-parameter -Wno-implicit-fallthrough -D_POSIX_C_SOURCE=200112L
DIR=NewProxy
DEPS=$(DIR)/buffer.h $(DIR)/doh.h $(DIR)/parser.h $(DIR)/parser_num.h $(DIR)/parser_http.h $(DIR)/parser_doh.h $(DIR)/parser_utils.h
OBJ=$(DEPS:.h=.o)
TESTS=doh_test parser_test

# Variables para doh Server
## Al modificar el puerto, recordar tambien modificar dicho valor en Proxy/doh.c
DOCKER=sudo docker
DOH_PORT=8080
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
%_test: $(OBJ)
	$(CC) -c -o $@.o $(CCFLAGS) $(DIR)/$@.c
	$(CC) -o $@ $^ $@.o $(CCFLAGS)
	rm -rf $@.o

.PHONY: tests
tests: $(TESTS)
	time ./doh_test
	time ./parser_test

.PHONY: clean
clean:
	rm -rf $(DIR)/*.o $(DIR)/*.out $(DIR)/*.dSYM *.o *.bin *.out *_test
