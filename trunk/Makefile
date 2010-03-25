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

CC = gcc

CFLAGS = -O2 -Wall $(shell libgnutls-config --cflags)

LDFLAGS = $(shell libgnutls-config --libs)

OBJS = gunnel.o tls.o

SERVICE = gunnel

HEADERS = gunnel.h

%.o: %.c $(HEADERS)
	$(CC) $(CFLAGS) -c -o $@ $<

$(SERVICE): $(OBJS)
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ $^

.PHONY: clean rensa

clean rensa:
	rm -f $(OBJS) $(SERVICE)