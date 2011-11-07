#
# Test suite for the TLS Tunnel tool.
#
# Author: Mats Erik Andersson <meand@users.berlios.de>, 2010.
#
# License: EUPLv1.0
#
#
# vim: set sw=4 ts=4
#

ALL = port_parsing

CFLAGS += -O2 -pedantic -Wall $(shell pkg-config --cflags gnutls)

LDFLAGS += $(shell pkg-config --libs gnutls)

port_parsing: port_parsing.c ../utils.o
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ $^
	./$@

../utils.o:
	$(MAKE) -C .. utils.o

.PHONY: rensa clean all

all: $(ALL)

rensa clean:
	rm -f port_parsing
