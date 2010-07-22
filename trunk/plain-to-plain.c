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
#include <string.h>

#include <getopt.h>

#define _INCLUDE_EXTERNALS	1
#include "gunnel.h"

#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <sys/wait.h>
#include <grp.h>
#include <pwd.h>

static const char options_string[] = "hl:r:g:u:o";

/* Semaphores for flow control. */
static int show_usage = 0;
static int again = 1;

/* Drop privileges, become daemon. */
int underpriv_daemon_mode(void);

/* Traffic exchanger. */
static void transmitter(int td, int rd);

/* Looping for incoming clients. */
static int accept_loop(int sd, char *rhost, char *rport);

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
						"\n\n",
				progname);

	printf("Active settings:\n"
			"\tProcess owner:   %s\n"
			"\tProcess group:   %s\n"
			"\tLocal port:      %s\n"
			"\tRemote port:     %s\n"
			"\tOne shot server: %s\n",
			cover_empty_string(user_name),
			cover_empty_string(group_name),
			cover_empty_string(local_port_string),
			cover_empty_string(remote_port_string),
			again ? "false" : "true"
			);
	exit(EXIT_FAILURE);
}; /* show_info(char *) */

/**
 * signal_responder  --  respond to select signals
 */

static void signal_responder(int sig) {
	switch (sig) {
		case SIGTERM:
			again = 0;
			break;
		case SIGCHLD:
			while ( waitpid(-1, NULL, WNOHANG) > 0 )
				;
		default:
			break;
	}
}; /* signal_responder(int) */

/*
 * Main control for this subsystem.
 */
int plain_to_plain(int argc, char *argv[]) {
	int opt, rc, sd = -1;
	char *lhost, *rhost;
	char *lport, *rport;
	struct addrinfo hints, *ai, *aiptr;

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

	memset(&hints, '\0', sizeof(hints));
	hints.ai_socktype = SOCK_STREAM;
	hints.ai_family = AF_UNSPEC;
#if defined(__linux__) || defined(__FreeBSD__)
	hints.ai_flags = AI_PASSIVE | AI_ADDRCONFIG;
#else
	hints.ai_flags = AI_PASSIVE;
#endif

	if ( (rc = getaddrinfo(lhost, lport, &hints, &aiptr)) ) {
		fprintf(stderr, "getaddrinfo: %s\n", gai_strerror(rc));
		return EXIT_FAILURE;
	}

	for ( ai = aiptr; ai; ai = ai->ai_next ) {
		int one = 1;

		if ( (sd = socket(ai->ai_family, ai->ai_socktype, ai->ai_protocol)) < 0 )
			continue;

		setsockopt(sd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));

		if ( bind(sd, ai->ai_addr, ai->ai_addrlen) == 0 )
			if ( listen(sd, 5) == 0 )
				break;	/* Successful. */

		close(sd);
		sd = -1;
	}

	freeaddrinfo(aiptr);

	if ( ai == NULL ) {
		fprintf(stderr, "Could not bind to local address.\n");
		return EXIT_FAILURE;
	}

	if ( (rc = underpriv_daemon_mode()) != GUNNEL_SUCCESS )
		return rc;

	/* Put the listener to work. */
	rc = accept_loop(sd, rhost, rport);

	close(sd);

	return rc;
}; /* plain_to_plain(int, char *[]) */

/**
 * transmitter  --  send data to and fro
 */

static void transmitter(int td, int rd) {
	ssize_t n;
	int maxfd;
	fd_set fdset;
	char recvbuf[2048];

	maxfd = (rd > td) ? rd : td;

	while(1) {

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

			n = send(rd, &recvbuf, n, 0);
			continue;
		}

		if (FD_ISSET(rd, &fdset)) {
			n = recv(rd, &recvbuf, sizeof(recvbuf), 0);

			if ( (n < 0) && (errno == EINTR) )
				continue;

			if (n <= 0)
				/* Error or orderly shutdown. */
				break;

			n = send(td, &recvbuf, n, 0);
		}
	}

	shutdown(rd, SHUT_RDWR);
	shutdown(td, SHUT_RDWR);
	close(rd);
	close(td);
}; /* transmitter(int, int) */

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
#if defined(__linux__) || defined(__FreeBSD__)
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

	exit(GUNNEL_SUCCESS);
}; /* accept_loop(int, char *, char *) */

/**
 * Change GID/UID and enter daemon mode.
 */
int underpriv_daemon_mode(void) {
	pid_t pid;
	struct passwd *passwd;
	struct group *group;

	signal(SIGTERM, signal_responder);
	signal(SIGCHLD, signal_responder);

	/* Forking and intending an underprivileged
	 * process owner. */
	switch (pid = fork()) {
		case -1:
			/* Failure */
			return GUNNEL_FORKING;
			break;
		case 0:
			/* Child process continues the work. */
			break;
		default:
			/* Parent process only exits. */
			exit(GUNNEL_SUCCESS);
			break;
	}

	if (setsid() < 0)
		return GUNNEL_FORKING;

	close(STDIN_FILENO);
	close(STDOUT_FILENO);

	signal(SIGHUP, SIG_IGN);
	signal(SIGINT, SIG_IGN);
	signal(SIGTSTP, SIG_IGN);

	chdir(FORKDIR);

	/* Change UID/GID in child process.
	 * The feasibility has previously been
	 * asserted. */
	group = getgrnam(group_name);
	passwd = getpwnam(user_name);

	/* Must begin with setgid! */
	if ( setgid(group->gr_gid) < 0 )
		return GUNNEL_FAILED_GID;

	/* Commence with UID. */
	if ( setuid(passwd->pw_uid) < 0 )
		return GUNNEL_FAILED_UID;

	switch (pid = fork()) {
		case -1:
			return GUNNEL_FORKING;
			break;
		case 0:
			/* Worker child process. */
			break;
		default:
			/* Intermediary parent is expendable. */
			exit(GUNNEL_SUCCESS);
			break;
	}

	/* Now all error messages are superfluous. */
	close(STDERR_FILENO);

	return GUNNEL_SUCCESS;
}; /* underpriv_daemon_mode(void) */
