# Makefile para proxy SOCKS5
GCC=gcc
GCCFLAGS= -pthread -g --std=c11 -pedantic -pedantic-errors -Wall -Wextra -Werror -Wno-unused-parameter -Wno-implicit-fallthrough -D_POSIX_C_SOURCE=200112L

.PHONY: clean
clean:
	rm -rf resources/*.o *.o *.bin *.out proxy
