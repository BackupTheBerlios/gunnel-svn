/*
 * utils.c  --  Common utility functions.
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
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/socket.h>
#include <netdb.h>
#include <pwd.h>
#include <grp.h>

#define _INCLUDE_EXTERNALS	1
#include "gunnel.h"

/*
 * Error messages.
 */
static struct {
	unsigned short num;
	char *msg;
} error_list[] = {
	{ GUNNEL_FORKING, "Unable to accomplish forking."},
	{ GUNNEL_INVALID_GID, "Invalid group name."},
	{ GUNNEL_INVALID_UID, "Invalid user name."},
	{ GUNNEL_FAILED_GID, "Unable to set desired GID."},
	{ GUNNEL_FAILED_UID, "Unable to set desired UID."},
	{ GUNNEL_INVALID_PORT, "Incorrect generalised port."},
	{ GUNNEL_ALLOCATION_FAILURE, "Unable to allocate memory."},
	{ GUNNEL_FAILED_REMOTE_CONN, "Unable to build remote connection."},
	{ GUNNEL_FAILED_REMOTELY, "Remote host failed."},
	{ 0, NULL}
};

/**
 * gunnel_error_message  --  produce an error description
 */

void gunnel_error_message(FILE * file, int num) {
	int j;

	if (num == 0)
		return;

	for (j=0; error_list[j].num; ++j) {
		if ( error_list[j].num != num )
			continue;

		fprintf(file, "%s\n", error_list[j].msg);
		return;
	}

	fprintf(file, "An unknown error has occurred.\n");
	return;
} /* gunnel_error_message(FILE *, int) */

/**
 * test_usr_grp  --  test a proposed gid/uid change
 *
 * Non-zero return indicates failures.
 * Confer to "gunnel.c" for values.
 */
int test_usr_grp(char *usr, char *grp) {
	struct passwd *passwd;
	struct group *group;
	pid_t pid;
	int rc;

	if ( (group = getgrnam(grp)) == NULL )
		return GUNNEL_INVALID_GID;

	if ( (passwd = getpwnam(usr)) == NULL )
		return GUNNEL_INVALID_UID;

	/* Fork off a process to see if setting of
	 * GID and UID is feasible. */
	if ( (pid = fork()) == 0 ) {
		/* Child process for testing. */

		/* Must begin with setgid! */
		if ( setgid(group->gr_gid) < 0 )
			exit(GUNNEL_FAILED_GID);

		/* Double check GID! */
		if ( getgid() != group->gr_gid )
			exit(GUNNEL_FAILED_GID);

		/* Continue with UID. */
		if ( setuid(passwd->pw_uid) < 0 )
			exit(GUNNEL_FAILED_UID);

		/* Double check UID! */
		if ( getuid() != passwd->pw_uid )
			exit(GUNNEL_FAILED_UID);

		/* All is well. */
		exit(GUNNEL_SUCCESS);
	} /* Child process. */

	/* Capture complete failure. */
	if (pid < 0)
		return GUNNEL_FORKING;

	/* Parent process must get return status of child. */
	waitpid(pid, &rc, 0);

	return WEXITSTATUS(rc);
} /* test_usr_grp(char *, char *) */

/**
 * decompose_port  --  parse a generalized port
 *
 * The identified parts are returned in *host, *port.
 * The corresponding strings should be return by free(3)
 * when done with.
 */
int decompose_port(const char *gport, char **host, char **port) {
	char *token;

	*host = *port = NULL;

	if (gport == NULL || gport[0] == '\0')
		return GUNNEL_INVALID_PORT;

	if ( (*host = strdup(gport)) == NULL )
		return GUNNEL_ALLOCATION_FAILURE;

	if ((token = strrchr(*host, ','))) {
		*token = '\0';
		++token;	/* Skip the separator character. */
	}

	if ( token == NULL || *token == '\0' ) {
		/* The generalised port has a single component.
		 * Decide on relevant specification type. */
		if ( *host[0] == '/' )
			/* Unix socket path! */
			return GUNNEL_SUCCESS;

		/* String goes as port specification! */
		*port = *host;
		*host = NULL;
		return GUNNEL_SUCCESS;
	}

	/* Both components have been detected. */

	if ( (*port = strdup(token)) == NULL ) {
		free(*host);
		*host = NULL;
		return GUNNEL_ALLOCATION_FAILURE;
	}

	/* Tidy an empty host. */
	if ( *host && (*host[0] == '\0') ) {
		free(*host);
		*host = NULL;
	}

	if (*host || *port)
		return GUNNEL_SUCCESS;
	else
		return GUNNEL_INVALID_PORT;
} /* decompose_port(const char *, char **, char **) */

/**
 * signal_responder  --  respond to select signals
 */

void signal_responder(int sig) {
	switch (sig) {
		case SIGTERM:
			exit(0);
			break;
		case SIGUSR1:
			again = 0;
			break;
		case SIGCHLD:
			while ( waitpid(-1, NULL, WNOHANG) > 0 )
				;
		default:
			break;
	}
} /* signal_responder(int) */

/**
 * route_content  --  get content from source, send to sink
 */

#if 0
int route_content(int source, int sink, int flags) {
}; /* route_content(int, int, int) */
#endif

/**
 * Change GID/UID and enter daemon mode.
 */
int underpriv_daemon_mode(void) {
	pid_t pid;
	gid_t glist[1];
	struct passwd *passwd;
	struct group *group;

	signal(SIGTERM, signal_responder);
	signal(SIGUSR1, signal_responder);
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

	/* Make sure that root drops all supplementary groups.
	 * Since all other users cannot alter these, it makes
	 * no sense to test the return value.
	 *
	 * The value naught is intentional. */
	glist[0] = group->gr_gid;
	setgroups(0, glist);

	/* Continue with UID. */
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
} /* underpriv_daemon_mode(void) */

/**
 * get_listening_socket -- examine local host, get socket
 */

int get_listening_socket(char *lhost, char *lport) {
	int rc, sd = -1;
	struct addrinfo hints, *ai, *aiptr;

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
		return -1;
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
		return -1;
	}

	return sd;
} /* get_listening_socket(char *, char *) */
