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
#include <libintl.h>
#include <locale.h>

#define MESSAGE_LENGTH 256

#if _INCLUDE_EXTERNALS

extern char *certificate;
extern char *cafile;
extern char *keyfile;
extern char *ciphers;    

#endif /* _INCLUDE_EXTERNALS */

/* From tls.c */
int init_tls(char *str, int maxlen);

void deinit_tls(void);

int init_tls_session(int fd, char *str, int maxlen);

#endif /* _GUNNEL_H */
