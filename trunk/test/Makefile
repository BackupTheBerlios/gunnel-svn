#
# Test suite for the TLS Tunnel tool.
#

port_parsing: port_parsing.c ../utils.o
	$(CC) -Wall -o $@ $^
	./$@

../utils.o:
	$(MAKE) -C .. utils.o

rensa clean:
	rm -f port_parsing
