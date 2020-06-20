# Makefile para proxy SOCKS5
GCC=clang
GCCFLAGS= -pthread -g --std=c11 -pedantic -pedantic-errors -Wall -Wextra -Werror -Wno-unused-parameter -Wno-unused-variable -Wno-implicit-fallthrough -D_POSIX_C_SOURCE=200112L
TARGET = main
FILES = $(wildcard *.c) $(wildcard DOH/*.c)
  all: $(TARGET)

  $(TARGET): $(TARGET).c $(INCLUDES)
	$(GCC) $(GCCFLAGS) -o $(TARGET) $(FILES)

.PHONY: clean
clean:
	rm -rf *.o *.o *.bin *.out *.dSYM main
