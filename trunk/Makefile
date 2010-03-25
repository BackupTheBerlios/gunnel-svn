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

CFLAGS = -O2 -Wall

OBJS = gunnel.o

SERVICE = gunnel

HEADERS = gunnel.h

%.o: %.c $(HEADERS)
	$(CC) $(CFLAGS) -c -o $@ $<

$(SERVICE): $(OBJS)
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ $^

.PHONY: clean rensa

clean rensa:
	rm -f $(OBJS) $(SERVICE)
