##
# Makefile para proxy SOCKS5
##

# Variables para compilador C
GCC=gcc
GCCFLAGS= -pthread -g --std=c11 -pedantic -pedantic-errors -Wall -Wextra -Werror -Wno-unused-parameter -Wno-implicit-fallthrough -D_POSIX_C_SOURCE=200112L

# Variables para doh Server
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

.PHONY: clean
clean:
	rm -rf resources/*.o *.o *.bin *.out
