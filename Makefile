CC      ?= cc
CFLAGS  ?= -O2 -Wall -Wextra -std=gnu11 -pthread
PREFIX  ?= /usr/local

SSL_CFLAGS  := $(shell pkg-config --cflags openssl 2>/dev/null)
SSL_LIBS    := $(shell pkg-config --libs openssl 2>/dev/null)
ifeq ($(SSL_LIBS),)
SSL_LIBS := -lssl -lcrypto
endif

SRC := src/canyon.c src/net.c src/socks5.c src/rand.c src/logbook.c src/ws.c src/tls.c
OBJ := $(SRC:.c=.o)
HDR := src/canyon.h src/net.h src/socks5.h src/rand.h src/logbook.h src/ws.h src/tls.h

BIN := canyon

all: $(BIN)

$(BIN): $(OBJ)
	$(CC) $(CFLAGS) -o $@ $(OBJ) $(SSL_LIBS)

%.o: %.c $(HDR)
	$(CC) $(CFLAGS) $(SSL_CFLAGS) -c -o $@ $<

install: $(BIN)
	install -m 0755 $(BIN) $(PREFIX)/bin/$(BIN)

uninstall:
	rm -f $(PREFIX)/bin/$(BIN)

test: $(BIN)
	./tests/smoke.sh

clean:
	rm -f $(BIN) $(OBJ)

.PHONY: all install uninstall test clean
