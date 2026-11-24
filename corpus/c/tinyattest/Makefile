# tinyattest build.
#
# Requires OpenSSL 3.5 or newer: the verifier session key uses ML-KEM, which
# earlier releases do not provide.
#
# Also requires wolfSSL 5.9.1 or newer configured --enable-xmss --enable-lms,
# for the long-term provisioning-record seals in src/seal_longterm.c. Both are
# opt-in at configure time and no package manager we use exposes them, so
# tools/build-all.sh builds wolfSSL from source and points CPPFLAGS and LDFLAGS
# at it. To build by hand, install such a wolfSSL and set those the same way.
#
# src/tls.c links libssl. src/win_cng.c is the Windows pre-key path through CNG:
# empty on every other platform, and compiled and linked against bcrypt by
# `make windows-check` with a mingw-w64 cross compiler (WINCC).

CC      ?= cc
CFLAGS  ?= -O2 -g -std=c11 -Wall -Wextra -Wpedantic
CPPFLAGS += -Iinclude
LDLIBS  += -lssl -lcrypto -lwolfssl
WINCC   ?= x86_64-w64-mingw32-gcc

BIN     := tinyattest
SRCS    := $(wildcard src/*.c)
OBJS    := $(SRCS:.c=.o)

.PHONY: all clean check windows-check

all: $(BIN)

$(BIN): $(OBJS)
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ $(OBJS) $(LDLIBS)

src/%.o: src/%.c include/tinyattest.h
	$(CC) $(CFLAGS) $(CPPFLAGS) -c -o $@ $<

check: $(BIN)
	./$(BIN) etc/tinyattest.conf

windows-check:
	$(WINCC) -std=c11 -Wall -Wextra -Wpedantic -shared -o tinyattest-cng.dll src/win_cng.c -lbcrypt

clean:
	rm -f $(BIN) $(OBJS) tinyattest-cng.dll
