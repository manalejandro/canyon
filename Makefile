CC      ?= cc
CFLAGS  ?= -O2 -Wall -Wextra -std=gnu11 -pthread
PREFIX  ?= /usr/local

SRC := src/canyon.c src/net.c src/socks5.c src/rand.c src/logbook.c
OBJ := $(SRC:.c=.o)
HDR := src/canyon.h src/net.h src/socks5.h src/rand.h src/logbook.h

BIN := canyon

all: $(BIN)

$(BIN): $(OBJ)
	$(CC) $(CFLAGS) -o $@ $(OBJ)

%.o: %.c $(HDR)
	$(CC) $(CFLAGS) -c -o $@ $<

install: $(BIN)
	install -m 0755 $(BIN) $(PREFIX)/bin/$(BIN)

uninstall:
	rm -f $(PREFIX)/bin/$(BIN)

test: $(BIN)
	./tests/smoke.sh

clean:
	rm -f $(BIN) $(OBJ)

.PHONY: all install uninstall test clean
