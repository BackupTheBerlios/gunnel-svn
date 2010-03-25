/*
 * gunnel.h  --  common inclusions
 *
 * Author: Mats Erik Andersson <meand@users.berlios.de>, 2010.
 *
 * License: EUPL v1.0.
 */

#ifndef _GUNNEL_H
#  define _GUNNEL_H	1

#include <errno.h>
#include <libintl.h>
#include <locale.h>

#if _INCLUDE_EXTERNALS

extern char *certificate = NULL;
extern char *cafile      = NULL;
extern char *keyfile     = NULL;

#endif /* _INCLUDE_EXTERNALS */

#endif /* _GUNNEL_H */
