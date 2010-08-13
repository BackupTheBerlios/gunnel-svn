/*
 * plugins.h  --  declaration of subsystems
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

#ifndef _PLUGINS_H
#  define _PLUGINS_H 1

/* typedef int (*func)(int argc, char *argv[]) plugin_fcn; */

extern int plain_to_tls(int argc, char *argv[]);
extern int tls_to_plain(int argc, char *argv[]);
extern int plain_to_plain(int argc, char *argv[]);
extern int tls_snooper(int argc, char *argv[]);
extern int plain_snooper(int argc, char *argv[]);

#endif /* _PLUGINS_H */
