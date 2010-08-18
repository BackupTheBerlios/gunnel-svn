/*
 * tls.c  --  Authorisation and encryption.
 *
 * Author: Mats Erik Andersson <meand@users.berlios.de>, 2010.
 *
 * License: EUPL v1.0.
 *
 * $Id$
 */

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>

#include <gnutls/gnutls.h>
#include <gnutls/x509.h>

#define _INCLUDE_EXTERNALS	1
#include "gunnel.h"

# ifndef DH_PARAMS_LEN
#   define DH_PARAMS_LEN	1024
# endif

/* Globals for use by libgnutls. */
gnutls_certificate_credentials_t x509_cred;
gnutls_dh_params_t dh_params;
gnutls_priority_t tls_priority_cache;

void deinit_tls_server(void) {
	gnutls_priority_deinit(tls_priority_cache);
	gnutls_certificate_free_credentials(x509_cred);
	gnutls_global_deinit();
} /* deinit_tls_server(void) */

void deinit_tls_client(void) {
	gnutls_certificate_free_credentials(x509_cred);
	gnutls_global_deinit();
} /* deinit_tls_client(void) */

int init_tls_server(char *message, int len) {
	int rc;

	gnutls_global_init();

	gnutls_certificate_allocate_credentials(&x509_cred);
	if (cafile && strlen(cafile) &&
		(rc = gnutls_certificate_set_x509_trust_file(x509_cred,
								cafile, GNUTLS_X509_FMT_PEM) <=0)){
		strncpy(message, "No valid CA-chain.", len);
		if (len > 1)
			message[len - 1] = '\0';
		gnutls_global_deinit();
		return EXIT_FAILURE;
	}

	rc = gnutls_certificate_set_x509_key_file(x509_cred,
							certificate, keyfile, GNUTLS_X509_FMT_PEM);
	if (rc != GNUTLS_E_SUCCESS) {
		gnutls_certificate_free_credentials(x509_cred);
		gnutls_global_deinit();
		snprintf(message, len, "Certificate: %s", gnutls_strerror(rc));
		if (len > 1)
			message[len - 1] = '\0';
		return EXIT_FAILURE;
	}

	gnutls_dh_params_init(&dh_params);
	gnutls_dh_params_generate2(dh_params, DH_PARAMS_LEN);

	rc = gnutls_priority_init(&tls_priority_cache, ciphers, NULL);
	if (rc != GNUTLS_E_SUCCESS) {
		gnutls_certificate_free_credentials(x509_cred);
		gnutls_global_deinit();
		snprintf(message, len, "Priority string: %s\nCipher priority: %s",
				ciphers, gnutls_strerror(rc));
		if (len > 1)
			message[len - 1] = '\0';
		return EXIT_FAILURE;
	}

	gnutls_certificate_set_dh_params(x509_cred, dh_params);

	snprintf(message, len, "GnuTLS certificate loaded successfully.\n"
				"Using ciphers \"%s\".\n", ciphers);
	if (len > 0)
		message[len - 1] = '\0';

    return EXIT_SUCCESS;
} /* init_tls_server(char *, int) */

int init_tls_client(char *message, int len) {
	int rc;

	gnutls_global_init();

	gnutls_certificate_allocate_credentials(&x509_cred);
	if (cafile && strlen(cafile) &&
		(rc = gnutls_certificate_set_x509_trust_file(x509_cred,
								cafile, GNUTLS_X509_FMT_PEM) <=0)){
		strncpy(message, "No valid CA-chain.", len);
		if (len > 1)
			message[len - 1] = '\0';
		gnutls_global_deinit();
		return EXIT_FAILURE;
	}

	rc = gnutls_certificate_set_x509_key_file(x509_cred,
							certificate, keyfile, GNUTLS_X509_FMT_PEM);
	if (rc != GNUTLS_E_SUCCESS) {
		gnutls_certificate_free_credentials(x509_cred);
		gnutls_global_deinit();
		snprintf(message, len, "Certificate: %s", gnutls_strerror(rc));
		if (len > 1)
			message[len - 1] = '\0';
		return EXIT_FAILURE;
	}

	gnutls_dh_params_init(&dh_params);
	gnutls_dh_params_generate2(dh_params, DH_PARAMS_LEN);

#if 0
	rc = gnutls_priority_init(&tls_priority_cache, ciphers, NULL);
	if (rc != GNUTLS_E_SUCCESS) {
		gnutls_certificate_free_credentials(x509_cred);
		gnutls_global_deinit();
		snprintf(message, len, "Priority string: %s\nCipher priority: %s",
				ciphers, gnutls_strerror(rc));
		if (len > 1)
			message[len - 1] = '\0';
		return EXIT_FAILURE;
	}
#endif

	gnutls_certificate_set_dh_params(x509_cred, dh_params);

	snprintf(message, len, "GnuTLS certificate loaded successfully.\n"
				"Using ciphers \"%s\".\n", ciphers);
	if (len > 0)
		message[len - 1] = '\0';

    return EXIT_SUCCESS;
} /* init_tls_client(char *, int) */

int init_tls_client_session(gnutls_session_t *session, char *message, int len) {
	int rc;
	const char *errmsg;

	rc = gnutls_init(session, GNUTLS_CLIENT);
	if (rc != GNUTLS_E_SUCCESS) {
		snprintf(message, len, "Session init: %s.\n", gnutls_strerror(rc));
		if (len > 1)
			message[len - 1] = '\0';
		return EXIT_FAILURE;
	}	

	rc = gnutls_priority_set_direct(*session, ciphers, &errmsg);
	if (rc != GNUTLS_E_SUCCESS) {
		snprintf(message, len, "Ciphers: %s.\n", errmsg);
		if (len > 1)
			message[len - 1] = '\0';
		gnutls_deinit(*session);
		return EXIT_FAILURE;
	}

	gnutls_credentials_set(*session, GNUTLS_CRD_CERTIFICATE, x509_cred);

	return EXIT_SUCCESS;
} /* init_tls_client_session(gnutls_session_t *, char *, int) */

int init_tls_server_session(gnutls_session_t *session, char *message, int len) {
	int rc;

	rc = gnutls_init(session, GNUTLS_SERVER);
	if (rc != GNUTLS_E_SUCCESS) {
		snprintf(message, len, "Session init: %s.\n", gnutls_strerror(rc));
		if (len > 1)
			message[len - 1] = '\0';
		return EXIT_FAILURE;
	}	

	rc = gnutls_priority_set(*session, tls_priority_cache);
	if (rc != GNUTLS_E_SUCCESS) {
		snprintf(message, len, "Ciphers: %s.\n", gnutls_strerror(rc));
		if (len > 1)
			message[len - 1] = '\0';
		gnutls_deinit(*session);
		return EXIT_FAILURE;
	}

	gnutls_credentials_set(*session, GNUTLS_CRD_CERTIFICATE, x509_cred);
	gnutls_certificate_server_set_request(*session, GNUTLS_CERT_REQUEST);

	return EXIT_SUCCESS;
} /* init_tls_server_session(gnutls_session_t *, char *, int) */

