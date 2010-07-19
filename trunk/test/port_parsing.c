/*
 * test/port_parsing.c  --  Examine port string detection.
 *
 * Author: Mats Erik Andersson <meand@users.berlios.de>, 2010.
 *
 * License: EUPL v1.0.
 *
 * $Id$
 */

#include <stdlib.h>
#include <unistd.h>
#include <stdio.h>
#include <string.h>

#include "../gunnel.h"

struct {
	int retval;
	char *gport;
	char *host;
	char *port;
} tcase[] = {
	/* Cases where gport is empty or null. */
	{ GUNNEL_INVALID_PORT, "", NULL, NULL},
	{ GUNNEL_INVALID_PORT, NULL, NULL, NULL},
	/* Valid unix socket. */
	{ GUNNEL_SUCCESS, "/var/run/gunnel,hej", "/var/run/gunnel", "hej"},
	/* Improperly terminated unix socket can recover. */
	{ GUNNEL_SUCCESS, "/var/run/gunnel,", "/var/run/gunnel", NULL},
	/* Rescue empty right-most port, when not a unix socket. */
	{ GUNNEL_SUCCESS, "ipv6.google.com,", NULL, "ipv6.google.com"},
	/* Simple port. */
	{ GUNNEL_SUCCESS, "https", NULL, "https"},
	/* Hostname and port. */
	{ GUNNEL_SUCCESS, "::1,smtp", "::1", "smtp"},
	/* With multiple commata, catch the right-most delimiter. */
	{ GUNNEL_SUCCESS, "adam,bero,caesar", "adam,bero", "caesar"},
	/* The next case is impossible outcome, thus halts. */
	{ GUNNEL_SUCCESS, NULL, NULL, NULL}
};

int main(int argc, char *argv[]) {
	int j, num = 0, retval;
	char *host, *port;

	fprintf(stderr, "Tests in decomposing a generalized port.\n");

	for (j = 0; (tcase[j].gport != NULL)
				|| (tcase[j].retval != GUNNEL_SUCCESS); ++j) {
		retval = decompose_port(tcase[j].gport, &host, &port);

		if (argc > 1) {
			fprintf(stderr, "Setting gport = \"%s\", and receiving\n"
					"        host = \"%s\", port = \"%s\";\n",
					tcase[j].gport, host, port);
			fprintf(stderr, "    expecting host = \"%s\", port = \"%s\".\n",
					tcase[j].host, tcase[j].port);
		}

		if ( (tcase[j].retval != retval)
				|| ( (tcase[j].port == NULL) && (port != NULL) )
				|| ( (tcase[j].port != NULL) && (port == NULL) )
				|| ( (port != NULL) && strcmp(tcase[j].port, port) )
				|| ( (tcase[j].host == NULL) && (host != NULL) )
				|| ( (tcase[j].host != NULL) && (host == NULL) )
				|| ( (host != NULL) && strcmp(tcase[j].host, host) ) ) {
			++num;
			fprintf(stderr, "Failure for gport = \"%s\".\n", tcase[j].gport);
		}
	}

	if (num)
		fprintf(stderr, "Failed at %d case out of %d possible.\n", num, j);
	else
		fprintf(stderr, "Successfully decomposed %d port descriptions.\n", j);

	return num;
}; /* main() */
