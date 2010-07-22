/*
 * gunnel.c  --  logic and supervision
 *
 * Author: Mats Erik Andersson <meand@users.berlios.de>, 2010.
 *
 * License: EUPL v1.0.
 *
 * $Id$
 */

/*
 * vim: set sw=4 ts=4
 */

#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>

#include "plugins.h"

#define _INCLUDE_EXTERNALS 0
#include "gunnel.h"

/* This is the main executable, thus is
 * owns the globally defined variables. */

/* Process descriptions. */
char *user_name = "nobody";
char *group_name = "nogroup";

/* Authorisation entities. */
char *certificate	= NULL;
char *cafile		= NULL;
char *keyfile		= NULL;
char *ciphers		= "NORMAL";

/* Tunnel constituents. */
char *local_port_string = NULL;
char *remote_port_string = NULL;

/* Looping control. */
int again = 1;

/* Pugin descriptors. */
static struct {
	char *name;
	int (*func)(int argc, char *argv[]);
} plugins[] = {
#if USE_PLAIN_TO_TLS
	{ "plain-to-tls", plain_to_tls },
#endif
#if USE_TLS_TO_PLAIN
	{ "tls-to-plain", tls_to_plain },
#endif
#if USE_PLAIN_TO_PLAIN
	{ "plain-to-plain", plain_to_plain },
#endif
#if USE_TLS_SNOOP
	{ "tls-snoop", tls_snooper },
#endif
#if USE_PLAIN_SNOOP
	{ "plain-snoop", plain_snooper },
#endif
	{ NULL, NULL }
};	/* plugins[] */

/*
 * usage() -- display existent subsystems.
 */

void usage(char *prog) {
	int j;

	printf("Usage: %s service options\n", prog);
	printf("\nHere \"service\" is either of\n");

	for (j = 0; plugins[j].func; ++j)
		printf("        %s\n", plugins[j].name);

	printf("\nDisplay a subsystem's usage by calling\n\n"
			"    %s service -h\n\n", prog);

	exit(0);
} /* usage(char *) */

/*
 * main() -- detect the relevant subsystem and hand over execution.
 */

int main(int argc, char *argv[]) {
	int j, found = 0;

	setlocale(LC_ALL, "");

	if (argc == 1)
		usage(argv[0]); /* No return. */

	for (j = 0; plugins[j].name; ++j) {
		if ( plugins[j].func == NULL
				|| strcmp(argv[1], plugins[j].name) )
			continue;

		found = 1;
		break;
	}

	if (! found) {
		printf("Unknown subsystem: %s\n\n", argv[1]);
		usage(argv[0]); /* No return. */
	}

	/* Invoke the validated subsystem, recalling
	 * to transfer the remaining arguments. */

	return plugins[j].func(--argc, &argv[1]);
} /* main(int, char *[]) */
