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
	{ GUNNEL_INVALID_GID, "Invalid group name."},
	{ GUNNEL_INVALID_UID, "Invalid user name."},
	{ GUNNEL_FAILED_GID, "Unable to set desired GID."},
	{ GUNNEL_FAILED_UID, "Unable to set desired UID."},
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
}; /* gunnel_error_message(FILE *, int) */

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

		/* Commence with UID. */
		if ( setuid(passwd->pw_uid) < 0 )
			exit(GUNNEL_FAILED_UID);

		/* Double check UID! */
		if ( getuid() != passwd->pw_uid )
			exit(GUNNEL_FAILED_UID);

		/* All is well. */
		exit(GUNNEL_SUCCESS);
	} /* Child process. */

	/* Parent process must get return status of child. */
	waitpid(pid, &rc, 0);

	return WEXITSTATUS(rc);
}; /* test_usr_grp(char *, char *) */

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

	return GUNNEL_SUCCESS;
}; /* decompose_port(const char *, char **, char **) */
