CC = gcc
DBUG = -g
CCFLAGS = -O2 -Wall -pedantic
LIBSSL = -lssl -lcrypto
LDFLAGS=  -L/usr/local/opt/openssl/lib
CPPFLAGS= -I/usr/local/opt/openssl/include

TARGETS = cryptool

UNAME_S := $(shell uname -s)
    ifeq ($(UNAME_S),Darwin)
        CCFLAGS += $(LDFLAGS)
		CCFLAGS += $(CPPFLAGS)
    endif

all: $(TARGETS)

cryptool: cryptool.c
	$(CC) $(CCFLAGS) $(DBUG) -o $@ $< $(LIBSSL)

clean:
	rm -f $(TARGETS)
