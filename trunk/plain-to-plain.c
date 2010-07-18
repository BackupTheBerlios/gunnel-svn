/*
 * plain_to_plain.c  --  receive plain, forward plain
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

#include <getopt.h>

#define _INCLUDE_EXTERNALS	1
#include "gunnel.h"

static const char options_string[] = "hl:r:g:u:";

/* Semaphores for flow control. */
static int show_usage = 0;

/* Return "none" if argument is null. */
static inline const char *cover_empty_string(const char *str) {
	return str ? str : "none";
}; /* cover_empty_string(const char *) */

/* Display usage and instantiated settings. */
static void show_info(char *progname) {
	printf("Usage: %s " LOCAL_PORT_STR
						REMOTE_PORT_STR
						TUNNEL_USR_STR
						TUNNEL_GRP_STR
						"\n\n",
				progname);

	printf("Active settings:\n"
			"\tProcess owner:   %s\n"
			"\tProcess group:   %s\n"
			"\tLocal port:      %s\n"
			"\tRemote port:     %s\n",
			cover_empty_string(user_name),
			cover_empty_string(group_name),
			cover_empty_string(local_port_string),
			cover_empty_string(remote_port_string)
			);
	exit(EXIT_FAILURE);
}; /* show_info(char *) */

/*
 * Main control for this subsystem.
 */
int plain_to_plain(int argc, char *argv[]) {
	int opt, rc;

	while ( (opt = getopt(argc, argv, options_string)) != -1 ) {
		switch (opt) {
			case 'h':	show_usage = 1;
						break;
			case LOCAL_PORT:
						local_port_string = optarg;
						break;
			case REMOTE_PORT:
						remote_port_string = optarg;
						break;
			case TUNNEL_USR:
						user_name = optarg;
						break;
			case TUNNEL_GRP:
						group_name = optarg;
						break;
			case '?':
			default:
						fprintf(stderr, "\n");
						show_usage = 1;
						break;
		}
	}

	/* Prepare any settings. */

	if (show_usage)
		/* Never returns. */
		show_info(argv[0]);

	/* Check feasibility of GID-UID changes. */
	if ( (rc = test_usr_grp(user_name, group_name)) ) {
		gunnel_error_message(stderr, rc);
		return EXIT_FAILURE;
	}

	return EXIT_SUCCESS;
}; /* plain_to_plain(int, char *[]) */
