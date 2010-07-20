/*
 * gunnel.h  --  common inclusions
 *
 * Author: Mats Erik Andersson <meand@users.berlios.de>, 2010.
 *
 * License: EUPL v1.0.
 *
 * $Id$
 */

#ifndef _GUNNEL_H
#  define _GUNNEL_H	1

#include <errno.h>
#include <locale.h>

#define MESSAGE_LENGTH 256

#ifndef FORKDIR
#  if defined(__OpenBSD__) || defined(__FreeBSD__)
#    define FORKDIR	"/var/empty"
#  else
#    define FORKDIR	"/"
#  endif
#endif

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
#define TUNNEL_USR		'u'
#define TUNNEL_USR_STR	"[-u uid] "
#define TUNNEL_GRP		'g'
#define TUNNEL_GRP_STR	"[-g gid] "
#define ONE_SHOT		'o'
#define ONE_SHOT_STR	"[-o] "

/* Enumeration of identified errors. */
enum {
	GUNNEL_SUCCESS = 0,
	GUNNEL_FORKING,
	GUNNEL_INVALID_GID,
	GUNNEL_INVALID_UID,
	GUNNEL_FAILED_GID,
	GUNNEL_FAILED_UID,
	GUNNEL_INVALID_PORT,
	GUNNEL_ALLOCATION_FAILURE,
	GUNNEL_FAILED_REMOTE_CONN,
	GUNNEL_FAILED_REMOTELY,
};

#if _INCLUDE_EXTERNALS

extern char *local_port_string;
extern char *remote_port_string;
extern char *certificate;
extern char *cafile;
extern char *keyfile;
extern char *ciphers;    
extern char *user_name;
extern char *group_name;

#endif /* _INCLUDE_EXTERNALS */

/* From tls.c */
int init_tls(char *str, int maxlen);

void deinit_tls(void);

int init_tls_session(int fd, char *str, int maxlen);

/* From utils.c */
void gunnel_error_message(FILE * file, int num);

int test_usr_grp(char *usr, char *grp);

int decompose_port(const char *gport, char **host, char **port);

int route_content(int source, int sink, int flags);
#endif /* _GUNNEL_H */
