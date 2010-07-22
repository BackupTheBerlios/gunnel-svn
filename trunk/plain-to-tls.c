/*
 * plain_to_tls.c  --  receive plain, forward TLS
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

static const char options_string[] = "hl:r:g:u:c:k:a:C:o";

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
						ONE_SHOT_STR
						"\n\t\t    "
						CERT_FILE_STR
						CA_FILE_STR
						KEY_FILE_STR
						CIPHER_POLICY_STR
						"\n\n",
				progname);

	printf("Active settings:\n"
			"\tProcess owner:   %s\n"
			"\tProcess group:   %s\n"
			"\tLocal port:      %s\n"
			"\tRemote port:     %s\n"
			"\tOne shot server: %s\n"
			"\tCertificate:     %s\n"
			"\tKey file:        %s\n"
			"\tCA-chain:        %s\n"
			"\tCipher policy:   %s\n",
			cover_empty_string(user_name),
			cover_empty_string(group_name),
			cover_empty_string(local_port_string),
			cover_empty_string(remote_port_string),
			again ? "false" : "true",
			cover_empty_string(certificate),
			cover_empty_string(keyfile),
			cover_empty_string(cafile),
			ciphers
			);
	exit(EXIT_FAILURE);
}; /* show_info(char *) */

/*
 * Main control for this subsystem.
 */
int plain_to_tls(int argc, char *argv[]) {
	int opt, rc, sd = -1;
	char message[MESSAGE_LENGTH] = "";
	char *lhost, *lport;
	char *rhost, *rport;

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
			case CERT_FILE:
						certificate = optarg;
						break;
			case CA_FILE:
						cafile = optarg;
						break;
			case KEY_FILE:
						keyfile = optarg;
						break;
			case CIPHER_POLICY:
						ciphers = optarg;
						break;
			case TUNNEL_USR:
						user_name = optarg;
						break;
			case TUNNEL_GRP:
						group_name = optarg;
						break;
			case ONE_SHOT:
						again = 0;
						break;
			case '?':
			default:
						fprintf(stderr, "\n");
						show_usage = 1;
						break;
		}
	}

	/* Prepare any settings. */

	/* Implicit key should be bundled with the certificate. */
	if ( ! keyfile )
		keyfile = certificate;

	if (show_usage)
		/* Never returns. */
		show_info(argv[0]);

	/* Check feasibility of GID-UID changes. */
	if ( (rc = test_usr_grp(user_name, group_name)) ) {
		gunnel_error_message(stderr, rc);
		return EXIT_FAILURE;
	}

	if ( local_port_string == NULL
			|| remote_port_string == NULL ) {
		fprintf(stderr, "Missing port descriptions.\n");
		return EXIT_FAILURE;
	}

	if ( (rc = decompose_port(local_port_string, &lhost, &lport)) ) {
		fprintf(stderr, "Local port: ");
		gunnel_error_message(stderr, rc);
		return EXIT_FAILURE;
	}

	if ( (rc = decompose_port(remote_port_string, &rhost, &rport)) ) {
		fprintf(stderr, "Remote port: ");
		gunnel_error_message(stderr, rc);
		return EXIT_FAILURE;
	}

	/* Initiate Libgnutls with certificate, key, etcetera. */
	if (init_tls(message, sizeof(message))) {
		fprintf(stderr, "%s\nInit TLS failed!\n", message);
		return EXIT_FAILURE;
	}

	fprintf(stderr, "%s", message);
	atexit(deinit_tls);

	if ( (sd = get_listening_socket(lhost, lport)) < 0 )
		return EXIT_FAILURE;

	return EXIT_SUCCESS;
}; /* plain_to_tls(int, char *[]) */
