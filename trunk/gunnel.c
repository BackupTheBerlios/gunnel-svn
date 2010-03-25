/*
 * gunnel.c  --  logic and supervision
 *
 * Author: Mats Erik Andersson <meand@users.berlios.de>, 2010.
 *
 * License: EUPL v1.0.
 */

/*
 * vim: set sw=4 ts=4
 */

#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>

#include <getopt.h>

#define _INCLUDE_EXTERNALS	0
#include "gunnel.h"

/* Authorisation entities. */
char *certificate	= NULL;
char *cafile		= NULL;
char *keyfile		= NULL;
char *ciphers		= "NORMAL";

/* Tunnel constituents. */
char *local_port_string = NULL;
char *remote_port_string = NULL;

/* Synonyms for option flags. */
#define LOCAL_PORT		'l'
#define LOCAL_PORT_STR	"[-l port] "
#define REMOTE_PORT		'r'
#define REMOTE_PORT_STR	"[-r port] "
#define CERT_FILE		'c'
#define CERT_FILE_STR	"[-c file] "
#define CA_FILE			'a'
#define CA_FILE_STR		"[-a file] "
#define KEY_FILE		'k'
#define KEY_FILE_STR	"[-k file] "
#define CIPHER_POLICY	'C'
#define CIPHER_POLICY_STR	"[-C string] "

static const char options_string[] = "hl:r:c:k:a:C:";

/* Semaphores for flow control. */
int show_usage = 0;

/* Return "none" if argument is null. */
inline const char *cover_empty_string(const char *str) {
	return str ? str : "none";
}; /* cover_empty_string(const char *) */

/* Display usage and instantiated settings. */
static void show_info(char *progname) {
	printf("Usage: %s " LOCAL_PORT_STR REMOTE_PORT_STR
				CERT_FILE_STR CA_FILE_STR KEY_FILE_STR
				CIPHER_POLICY_STR "\n\n",
				progname);

	printf("Active settings:\n"
			"\tCertificate:   %s\n"
			"\tKey file:      %s\n"
			"\tCA-chain:      %s\n"
			"\tCipher policy: %s\n",
			cover_empty_string(certificate),
			cover_empty_string(keyfile),
			cover_empty_string(cafile),
			ciphers);
	exit(EXIT_FAILURE);
}; /* show_info(char *) */

/*
 * Main control.
 */
int main(int argc, char *argv[]) {
	int opt;
	char message[MESSAGE_LENGTH] = "";

	setlocale(LC_ALL, "");

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

	/* Initiate Libgnutls with certificate, key, etcetera. */
	if (init_tls(message, sizeof(message))) {
		fprintf(stderr, "%s\nInit TLS failed!\n", message);
		return EXIT_FAILURE;
	}

	fprintf(stderr, "%s", message);

	deinit_tls();

	return EXIT_SUCCESS;
}; /* main(int, char *[]) */
