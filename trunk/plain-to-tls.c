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
#include <string.h>

#include <getopt.h>

#define _INCLUDE_EXTERNALS	1
#include "gunnel.h"

#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <sys/wait.h>

#include <gnutls/gnutls.h>

static const char options_string[] = "hl:r:g:u:c:k:a:C:o";

/* Message passing */
static char message[MESSAGE_LENGTH] = "";

/* Semaphores for flow control. */
static int show_usage = 0;

/* Traffic exchanger. */
static void transmitter(int td, int rd);

/* Looping for incoming clients. */
static int accept_loop(int sd, char *rhost, char *rport);

/* Return "none" if argument is null. */
static inline const char *cover_empty_string(const char *str) {
	return str ? str : "none";
} /* cover_empty_string(const char *) */

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
} /* show_info(char *) */

/*
 * Main control for this subsystem.
 */
int plain_to_tls(int argc, char *argv[]) {
	int opt, rc, sd = -1;
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
	if (init_tls_client(message, sizeof(message))) {
		fprintf(stderr, "%s\nInit TLS failed!\n", message);
		return EXIT_FAILURE;
	}

	fprintf(stderr, "%s", message);

	if ( (sd = get_listening_socket(lhost, lport)) < 0 ) {
		deinit_tls_client();
		return EXIT_FAILURE;
	}

	free(lhost);
	free(lport);

	/* Resign as much privilege as possible. */
	if ( (rc = underpriv_daemon_mode()) != GUNNEL_SUCCESS ) {
		deinit_tls_client();
		return EXIT_FAILURE;
	}

	atexit(deinit_tls_client);

	/* Put the listener to work. */
	rc = accept_loop(sd, rhost, rport);

	close(sd);

	return EXIT_SUCCESS;
} /* plain_to_tls(int, char *[]) */

/**
 * transmitter  --  send data to and fro
 */

static void transmitter(int td, int rd) {
	ssize_t n;
	int rc, maxfd, again = 1;
	fd_set fdset;
	char recvbuf[2048];
	gnutls_session_t session;

	if (init_tls_session(rd, &session, message, sizeof(message))
		!= EXIT_SUCCESS)
		again = 0;

	while(again) {
		rc = gnutls_handshake(session);
		if ((rc == GNUTLS_E_AGAIN) || (rc == GNUTLS_E_INTERRUPTED))
			continue;
		if (rc < 0)
			again = 0;
		break;
	}

	maxfd = (rd > td) ? rd : td;

	while(again) {

		FD_ZERO(&fdset);
		FD_SET(rd, &fdset);
		FD_SET(td, &fdset);
		if ( select(maxfd + 1, &fdset, NULL, NULL, NULL) < 0 ) {
			if (errno == EINTR)
				continue;

			break;	/* An error has occurred. Abort! */
		}

		/* Take care of out of band data first. */
		if (FD_ISSET(td, &fdset)) {
			n = recv(td, &recvbuf, sizeof(recvbuf), MSG_OOB);

			if (n > 1)
				send(rd, &recvbuf, n, MSG_OOB);
		}

		if (FD_ISSET(rd, &fdset)) {
			n = recv(rd, &recvbuf, sizeof(recvbuf), MSG_OOB);

			if (n > 0)
				send(td, &recvbuf, n, 0);
		}

		/* Orderly content now. */
		if (FD_ISSET(td, &fdset)) {
			n = recv(td, &recvbuf, sizeof(recvbuf), 0);

			if ( (n < 0) && (errno == EINTR) )
				continue;

			if (n <= 0)
				/* Error or orderly shutdown. */
				break;

			while(1) {
				n = gnutls_record_send(session, &recvbuf, n);
				if ((n == GNUTLS_E_AGAIN) || (n == GNUTLS_E_INTERRUPTED))
					continue;
				else
					break;
			}
			continue;
		}

		if (FD_ISSET(rd, &fdset)) {
			while(1) {
				n = gnutls_record_recv(session, &recvbuf, sizeof(recvbuf));
				if ((n == GNUTLS_E_AGAIN) || (n == GNUTLS_E_INTERRUPTED))
					continue;
				else
					break;
			}

			if (n <= 0)
				/* Error or orderly shutdown. */
				break;

			n = send(td, &recvbuf, n, 0);
		}
	}

	if (again) {
		gnutls_bye(session, GNUTLS_SHUT_RDWR);
		gnutls_deinit(session);
	}

	shutdown(rd, SHUT_RDWR);
	shutdown(td, SHUT_RDWR);
	close(rd);
	close(td);
} /* transmitter(int, int) */

static int accept_loop(int sd, char *rhost, char *rport) {
	int ret, td = -1, rd = -1;
	pid_t pid;
	socklen_t socklen;
	struct sockaddr_storage addr;
	struct addrinfo hints, *ai, *aiptr;

	do {
		socklen = sizeof(addr);

		if ( (td = accept(sd, (struct sockaddr *) &addr, &socklen)) < 0 ) {
			if (! again)
				break;
			if (errno == EINTR)
				continue;
			else
				continue;
		}

		memset(&hints, '\0', sizeof(hints));
		hints.ai_family = AF_UNSPEC;
		hints.ai_socktype = SOCK_STREAM;
#if defined(AI_ADDRCONFIG)
		hints.ai_flags = AI_ADDRCONFIG;
#endif

		if ( (ret = getaddrinfo(rhost, rport, &hints, &aiptr)) ) {
			shutdown(td, SHUT_RDWR);
			close(td);
			return GUNNEL_FAILED_REMOTE_CONN;
		}

		for (ai = aiptr; ai; ai = ai->ai_next) {
			if ( (rd = socket(ai->ai_family, ai->ai_socktype, ai->ai_protocol)) < 0 )
				continue;

			if ( connect(rd, ai->ai_addr, ai->ai_addrlen) < 0 ) {
				close(rd);
				rd = -1;
				continue;
			}

			/* Successfully connected. */
			break;
		}

		freeaddrinfo(aiptr);

		if (ai == NULL) {
			/* Failure when locating the remote host. */
			shutdown(td, SHUT_RDWR);
			close(td);
			return GUNNEL_FAILED_REMOTE_CONN;
		}

		/* At this stage the connection is working,
		 * only traffic remains. Time to finally
		 * fork off the working daemon. */

		switch (pid = fork()) {
			case -1:
				/* Failure to fork. Close everything down. */
				shutdown(rd, SHUT_RDWR);
				shutdown(td, SHUT_RDWR);
				close(rd);
				close(td);
				close(sd);
				exit(GUNNEL_FORKING);
			case 0:
				/* Working offspring. */
				/* The listening socket is no longer needed. */
				close(sd);
				/* Move somewhere relatively safe. */
				transmitter(td, rd);
				exit(GUNNEL_SUCCESS);
			default:
				/* This parent reports success. */
				close(td);
				close(rd);
				break;
		}

	} while (again);

	free(rhost);
	free(rport);
	exit(GUNNEL_SUCCESS);
} /* accept_loop(int, char *, char *) */
