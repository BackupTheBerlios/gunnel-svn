#!/usr/bin/make -f
#
# Makefile for Gunnel
#
# Author: Mats Erik Andersson <meand@users.berlios.de>, 2010.
#
# License: EUPLv1.0
#
#
# vim: set sw=4 ts=4
#

SERVICE = gunnel

ALL = $(SERVICE) tests

SUBSERVICE = -DUSE_PLAIN_TO_TLS=1 -DUSE_PLAIN_TO_PLAIN=1 -DUSE_TLS_TO_PLAIN=1

CC = gcc

CFLAGS += $(SUBSERVICE) -O2 -pedantic -Wall $(shell pkg-config --cflags gnutls)

LDFLAGS += $(shell pkg-config --libs gnutls)

OBJS = gunnel.o utils.o tls.o plain-to-tls.o plain-to-plain.o \
	tls-to-plain.o

HEADERS = gunnel.h plugins.h

$(SERVICE): $(OBJS)
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ $^

%.o: %.c $(HEADERS)
	$(CC) $(CFLAGS) -c -o $@ $<

.PHONY: clean rensa tests all

all: $(ALL)

tests:
	$(MAKE) -C test/ all

clean rensa:
	rm -f $(OBJS) $(SERVICE)
	$(MAKE) -C test/ clean
