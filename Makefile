##
# Makefile para proxy SOCKS5
##

# Variables para compilador C
CFLAGS=-pthread -g --std=c11 -pedantic -pedantic-errors -Wall -Wextra -Werror -Wno-unused-parameter -Wno-unused-variable -Wno-implicit-fallthrough -D_POSIX_C_SOURCE=200112L
DIR=Proxy
DOH_DIR=$(DIR)/DOH
TEST_DIR=Tests
TEST_C=$(wildcard $(TEST_DIR)/*.c)
DEPS=$(wildcard $(DIR)/*.h) $(wildcard $(DOH_DIR)/*.h)
OBJECTS=$(DEPS:.h=.o)
TEST_FILTER_OUT=$(DIR)/socks5.o $(DIR)/auth.o
EXECUTABLE=main

# Variables para doh Server
DOH_PORT=8053
DOH_IMAGE=doh-nginx
DOH_CONTAINER=doh-server

.PHONY: all
all: $(EXECUTABLE)

$(EXECUTABLE): $(OBJECTS)
	$(CC) -c -o $@.o $(CFLAGS) $(DIR)/$@.c
	$(CC) -o $@ $^ $@.o $(CFLAGS)

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
	$(CC) -c -o $@ $< $(CFLAGS)

# Tests
$(TEST_DIR)/%_test: $(filter-out $(TEST_FILTER_OUT),$(OBJECTS))
	$(CC) -c -o $@.o $(CFLAGS) $@.c
	$(CC) -o $@ $^ $@.o $(CFLAGS)

.PHONY: tests
tests: $(subst .c,,$(TEST_C))
	$(subst .c,; ,$(TEST_C))

.PHONY: clean
clean:
	rm -rf $(EXECUTABLE) $(EXECUTABLE).o $(OBJECTS) $(TEST_DIR)/*.o $(TEST_DIR)/*_test
