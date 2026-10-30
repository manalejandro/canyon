CC      ?= cc
CFLAGS  ?= -O2 -Wall -Wextra -std=gnu11 -pthread
PREFIX  ?= /usr/local

SSL_CFLAGS  := $(shell pkg-config --cflags openssl 2>/dev/null)
SSL_LIBS    := $(shell pkg-config --libs openssl 2>/dev/null)
ifeq ($(SSL_LIBS),)
SSL_LIBS := -lssl -lcrypto
endif

# ncurses for the interactive TUI (-T). Probe the available curses variants
# (wide-character first); when none compiles+links, the TUI is stubbed out
# with -DCANYON_NO_TUI and canyon builds without it.
TUI_IDX := $(shell \
  n=0; \
  for combo in \
    "$$(pkg-config --cflags ncursesw 2>/dev/null)|$$(pkg-config --libs ncursesw 2>/dev/null)" \
    "$$(pkg-config --cflags ncurses 2>/dev/null)|$$(pkg-config --libs ncurses 2>/dev/null)" \
    "|-lncursesw" \
    "|-lncurses"; do \
    n=$$((n+1)); \
    cfl=$${combo%%|*}; lib=$${combo#*|}; \
    [ -z "$$lib" ] && continue; \
    if printf 'int main(void){return 0;}\n' | $(CC) $$cfl -include ncurses.h -x c - -o /dev/null $$lib >/dev/null 2>&1; then \
      echo $$n; break; \
    fi; \
  done)
ifeq ($(TUI_IDX),1)
TUI_CFLAGS := $(shell pkg-config --cflags ncursesw 2>/dev/null)
TUI_LIBS   := $(shell pkg-config --libs ncursesw 2>/dev/null)
else ifeq ($(TUI_IDX),2)
TUI_CFLAGS := $(shell pkg-config --cflags ncurses 2>/dev/null)
TUI_LIBS   := $(shell pkg-config --libs ncurses 2>/dev/null)
else ifeq ($(TUI_IDX),3)
TUI_LIBS   := -lncursesw
else ifeq ($(TUI_IDX),4)
TUI_LIBS   := -lncurses
else
CFLAGS     += -DCANYON_NO_TUI
endif

SRC := src/canyon.c src/net.c src/socks5.c src/rand.c src/logbook.c src/ws.c src/tls.c src/tui.c
OBJ := $(SRC:.c=.o)
HDR := src/canyon.h src/net.h src/socks5.h src/rand.h src/logbook.h src/ws.h src/tls.h src/tui.h

BIN := canyon

all: $(BIN)

$(BIN): $(OBJ)
	$(CC) $(CFLAGS) -o $@ $(OBJ) $(SSL_LIBS) $(TUI_LIBS)

%.o: %.c $(HDR)
	$(CC) $(CFLAGS) $(SSL_CFLAGS) $(TUI_CFLAGS) -c -o $@ $<

install: $(BIN)
	install -m 0755 $(BIN) $(PREFIX)/bin/$(BIN)

uninstall:
	rm -f $(PREFIX)/bin/$(BIN)

test: $(BIN)
	./tests/smoke.sh

clean:
	rm -f $(BIN) $(OBJ)

.PHONY: all install uninstall test clean
