/*
 * TLS transport
 *
 *  Copyright (c) 2015-2017 by Farsight Security, Inc.
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 */

#include <config.h>
#include <axa/wire.h>

#include <openssl/conf.h>
#include <openssl/crypto.h>
#include <openssl/err.h>
#include <openssl/opensslconf.h>
#include <openssl/rand.h>
#include <pthread.h>
#include <sys/stat.h>
#include <unistd.h>
#include <string.h>


static char *certs_dir = NULL;

static char cipher_list0[] = TLS_CIPHERS;
static char *cipher_list = cipher_list0;

/* All apikey related TLS data and functions are in the 'axa_apikey_'
 * namespace. This is done to keep the apikey TLS implementation separate from
 * the legacy TLS implementation, preserve the ABI, and to ease the eventual
 * deprecation and removal of the TLS code from the code base. */
static bool tls_initialized = false;
static bool apikey_initialized = false;
static bool tls_srvr = false;
static bool apikey_srvr = false;
static bool tls_threaded = false;
static bool tls_cleaned = false;
static bool apikey_cleaned = false;
static pthread_t init_id;
static pthread_t apikey_init_id;
static int32_t init_critical;

static SSL_CTX *ssl_ctx;
static SSL_CTX *apikey_ssl_ctx;

#ifndef OPENSSL_THREADS
#error "this installation of OpenSSL lacks thread support"
#endif
struct CRYPTO_dynlock_value {
	pthread_mutex_t mutex;
};
static int num_locks;
static pthread_mutex_t *mutex_buf = NULL;



/* Convert an SSL error queue code to a string */
static char *
reason_string(unsigned long got_err)
{
	const char *ssl_str;
	char *str;

	ssl_str = ERR_reason_error_string(got_err);
	if (ssl_str != NULL)
		str = axa_strdup(ssl_str);
	else
		axa_asprintf(&str, "SSL error=%lu", got_err);
	return (str);
}

/* Make an AXA error string from the top of the error queue. */
static void AXA_PF(2,3)
q_pemsg(axa_emsg_t *emsg, const char *p, ...)
{
	char *qstr, *msg;
	va_list args;

	va_start(args, p);
	axa_vasprintf(&msg, p, args);
	va_end(args);
	qstr = reason_string(ERR_get_error());
	axa_pemsg(emsg, "%s: %s", msg, qstr);
	free(msg);
	free(qstr);
}

/* Deal with results from SSL_accept(), SSL_connect(), SSL_write(),
 * and SSL_read() */
static int
get_ssl_pemsg(axa_emsg_t *emsg, SSL *ssl, int ret, const char *p, ...)
{
	int ssl_errno;
	unsigned long qerr;
	char *msg, *qstr;
	va_list args;

	if (ret > 0)
		return (SSL_ERROR_NONE);

	ssl_errno = SSL_get_error(ssl, ret);
	switch (ssl_errno) {
	case SSL_ERROR_NONE:
	case SSL_ERROR_WANT_READ:
	case SSL_ERROR_WANT_WRITE:
		/* operation finished or must be repeated by the caller */
		return (ssl_errno);

	case SSL_ERROR_ZERO_RETURN:
		va_start(args, p);
		axa_asprintf(&msg, p, args);
		va_end(args);
		axa_pemsg(emsg, "%s: TLS/SSL connection closed", msg);
		free(msg);
		return (ssl_errno);

	case SSL_ERROR_SYSCALL:
		va_start(args, p);
		axa_asprintf(&msg, p, args);
		va_end(args);
		qerr = ERR_get_error();
		if (qerr != 0) {
			qstr = reason_string(qerr);
			axa_pemsg(emsg, "%s: %s", msg, qstr);
			free(qstr);
		} else if (ret == 0) {
			axa_pemsg(emsg, "%s: TLS/SSL EOF", msg);
		} else {
			axa_pemsg(emsg, "%s: %s", msg, strerror(errno));
		}
		free(msg);
		return (ssl_errno);

	case SSL_ERROR_SSL:
		va_start(args, p);
		axa_asprintf(&msg, p, args);
		va_end(args);
		qstr = reason_string(ERR_get_error());
		axa_pemsg(emsg, "%s: %s", msg, qstr);
		free(qstr);
		free(msg);
		return (ssl_errno);
	}

	va_start(args, p);
	axa_asprintf(&msg, p, args);
	va_end(args);
	axa_pemsg(emsg, "%s: unexpected SSL_ERROR %d", msg, ssl_errno);
	free(msg);
	return (ssl_errno);
}


/* Thread ID callback for OpenSSL */
static unsigned long
__attribute__((used)) id_function(void)
{
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wbad-function-cast"
	/* pthread_t is a pointer on some systems including FreeBSD */
	return ((unsigned long)pthread_self());
#pragma clang diagnostic pop
}

/* Lock or unlock a static (created at initialization) lock for OpenSSL */
static void
__attribute__((used)) locking_function(int mode, int n,
		 const char *file AXA_UNUSED, int line AXA_UNUSED)
{
	if (mode & CRYPTO_LOCK) {
		AXA_ASSERT(0 == pthread_mutex_lock(&mutex_buf[n]));
	} else {
		AXA_ASSERT(0 == pthread_mutex_unlock(&mutex_buf[n]));
	}
}

/* Create a "dynamic" lock for OpenSSL */
static struct CRYPTO_dynlock_value *
__attribute__((used)) dyn_create_function(const char *file AXA_UNUSED,
		int line AXA_UNUSED)
{
	struct CRYPTO_dynlock_value *value;

	value = (struct CRYPTO_dynlock_value *)
	axa_malloc(sizeof(struct CRYPTO_dynlock_value));
	AXA_ASSERT(0 == pthread_mutex_init(&value->mutex, NULL));
	return value;
}

/* Destroy a "dynamic" lock for OpenSSL */
static void
__attribute__((used)) dyn_destroy_function(struct CRYPTO_dynlock_value *l,
		     const char *file AXA_UNUSED, int line AXA_UNUSED)
{
	AXA_ASSERT(0 == pthread_mutex_destroy(&l->mutex));
	free(l);
}

/* Lock or unlock a "dynamic" lock */
static void
__attribute__((used)) dyn_lock_function(int mode,
		struct CRYPTO_dynlock_value *l, const char *file AXA_UNUSED,
		int line AXA_UNUSED)
{
	if (mode & CRYPTO_LOCK) {
		AXA_ASSERT(0 == pthread_mutex_lock(&l->mutex));
	} else {
		AXA_ASSERT(0 == pthread_mutex_unlock(&l->mutex));
	}
}

static bool
ck_certs_dir(axa_emsg_t *emsg, char *dir)
{
	AXA_ASSERT(init_critical == 1);

	if (dir != NULL) {
		if (certs_dir != NULL)
			free(certs_dir);
		certs_dir = dir;
	}

	if (*certs_dir == '\0') {
		axa_pemsg(emsg, "\"\" is an invalid certificates directory");
		return (false);
	}

	/* Tell the SSL library about the new directory only when it
	 * knows about the previous directory. */
	if (ssl_ctx != NULL
	    && 0 >= SSL_CTX_load_verify_locations(ssl_ctx, NULL, certs_dir)) {
		q_pemsg(emsg, "SSL_CTX_load_verify_locations(%s)", certs_dir);
		return (NULL);
	}

	return (true);
}

static bool
ck_env_certs_dir(axa_emsg_t *emsg, const char *name, const char *subdir)
{
	const char *val;
	char *dir;

	val = getenv(name);
	if (val == NULL)
		return (false);
	axa_asprintf(&dir, "%s/%s", val, subdir);
	return (ck_certs_dir(emsg, dir));
}

static bool
sub_tls_certs_dir(axa_emsg_t *emsg, const char *dir)
{

	if (dir != NULL)
		return (ck_certs_dir(emsg, axa_strdup(dir)));

	if (certs_dir != NULL)
		return (ck_certs_dir(emsg, NULL));

	/* Find a default if we are not supplied with a directory name. */
	if (ck_env_certs_dir(emsg, "AXACONF", "certs"))
		return (true);
	if (ck_env_certs_dir(emsg, "HOME", ".axa/certs"))
		return (true);
	return (ck_certs_dir(emsg, axa_strdup(AXACONFDIR"/certs")));
}

bool
axa_tls_certs_dir(axa_emsg_t *emsg, const char *dir)
{
	bool result;
	int i;

	/* This is not reentrant */
	i = __sync_add_and_fetch(&init_critical, 1);
	AXA_ASSERT(i == 1);

	result = sub_tls_certs_dir(emsg, dir);

	AXA_ASSERT(__sync_sub_and_fetch(&init_critical, 1) == 0);
	return (result);
}

const char *
axa_tls_cipher_list(axa_emsg_t *emsg, const char *list)
{
	int i;

	if (list == NULL || *list == '\0')
		return (cipher_list);

	/* This is not reentrant */
	i = __sync_add_and_fetch(&init_critical, 1);
	AXA_ASSERT(i == 1);

	if (cipher_list != cipher_list0)
		free(cipher_list);
	cipher_list = axa_strdup(list);

	if (ssl_ctx != NULL
	    && 0 >= SSL_CTX_set_cipher_list(ssl_ctx, cipher_list)) {
		q_pemsg(emsg, "SSL_CTX_set_cipher_list(%s)", cipher_list);
		i = __sync_sub_and_fetch(&init_critical, 1);
		AXA_ASSERT(i == 0);
		return (NULL);
	}

	i = __sync_sub_and_fetch(&init_critical, 1);
	AXA_ASSERT(i == 0);
	return (cipher_list);
}

bool
axa_tls_init(axa_emsg_t *emsg, bool srvr, bool threaded)
{
	DSA *dsa;
	DH *dh;
	EC_KEY *ecdh;
	int i;

	/* SSL_library_init() is not reentrant. */
	AXA_ASSERT(__sync_add_and_fetch(&init_critical, 1) == 1);

	/* Do not try to use OpenSSL after releasing it. */
	AXA_ASSERT(tls_cleaned == false);

	if (tls_initialized) {
		/* Require consistency. */
		AXA_ASSERT(tls_srvr == srvr && tls_threaded == threaded);

		/*
		 * Check that every initialization is just as threaded.
		 * No harm is done by using pthread_self() in unthreaded
		 * callers of this, because libaxa uses libnmsg which uses
		 * pthreads.
		 */
		if (!tls_threaded)
			AXA_ASSERT(pthread_self() == init_id);

		AXA_ASSERT(__sync_sub_and_fetch(&init_critical, 1) == 0);
		return (true);
	}

	tls_initialized = true;
	tls_srvr = srvr;
	tls_threaded = threaded;
	init_id = pthread_self();

	SSL_library_init();
	SSL_load_error_strings();

	OPENSSL_config(NULL);

	/*
	 * Turn on OpenSSL threading if needed.
	 */
	if (tls_threaded) {
		/* static locks */
		CRYPTO_set_id_callback(id_function);
		num_locks = CRYPTO_num_locks();
		if (num_locks != 0) {
			mutex_buf = axa_malloc(num_locks
					       * sizeof(pthread_mutex_t));
			for (i = 0; i < num_locks; i++)
				AXA_ASSERT(0 == pthread_mutex_init(&mutex_buf[i],
							NULL));
		}

		CRYPTO_set_locking_callback(locking_function);

		/* dynamic locks */
		CRYPTO_set_dynlock_create_callback(dyn_create_function);
		CRYPTO_set_dynlock_lock_callback(dyn_lock_function);
		CRYPTO_set_dynlock_destroy_callback(dyn_destroy_function);
	}

	ERR_clear_error();

	ssl_ctx = SSL_CTX_new(SSLv23_method());
	if (ssl_ctx == NULL) {
		q_pemsg(emsg, "SSL_CTX_new()");
		AXA_ASSERT(__sync_sub_and_fetch(&init_critical, 1) == 0);
		return (false);
	}

	/* Generate DSA parameters for DH because that is faster. */
	RAND_load_file("/dev/urandom", 128);
	dsa = DSA_new();
	if (dsa == NULL) {
		q_pemsg(emsg, "DSA_new()");
		AXA_ASSERT(__sync_sub_and_fetch(&init_critical, 1) == 0);
		return (false);
	}
	if (!DSA_generate_parameters_ex(dsa, 1024, NULL, 0,
					NULL, NULL, NULL)) {
		q_pemsg(emsg, "DSA_generate_parameters_ex()");
		AXA_ASSERT(__sync_sub_and_fetch(&init_critical, 1) == 0);
		return (false);
	}
	dh = DSA_dup_DH(dsa);
	if (dh == NULL) {
		q_pemsg(emsg, "DSA_dup_DH()");
		DSA_free(dsa);
		AXA_ASSERT(__sync_sub_and_fetch(&init_critical, 1) == 0);
		return (false);
	}
	DSA_free(dsa);
	if (!SSL_CTX_set_tmp_dh(ssl_ctx, dh)) {
		DH_free(dh);
		q_pemsg(emsg, "SSL_CTX_set_tmp_dh()");
		AXA_ASSERT(__sync_sub_and_fetch(&init_critical, 1) == 0);
		return (false);
	}
	DH_free(dh);

	ecdh = EC_KEY_new_by_curve_name(NID_X9_62_prime256v1);
	if (ecdh == NULL) {
		q_pemsg(emsg,
			  "EC_KEY_new_by_curve_name(NID_X9_62_prime256v1)");
		AXA_ASSERT(__sync_sub_and_fetch(&init_critical, 1) == 0);
		return (false);
	}
	SSL_CTX_set_tmp_ecdh(ssl_ctx, ecdh);
	EC_KEY_free(ecdh);

	SSL_CTX_set_mode(ssl_ctx,
			 SSL_MODE_ENABLE_PARTIAL_WRITE
			 | SSL_MODE_ACCEPT_MOVING_WRITE_BUFFER);

	/* Require a good certificate from the peer. */
	SSL_CTX_set_verify(ssl_ctx,
			   SSL_VERIFY_PEER
			   | SSL_VERIFY_FAIL_IF_NO_PEER_CERT,
			   NULL);

	/* Require self-signed certificates from clients. */
	if (!srvr)
		SSL_CTX_set_verify_depth(ssl_ctx, 0);

	/*
	 * Is SSL_OP_NO_SSLv2|SSL_OP_NO_SSLv3 needed?
	 */
	SSL_CTX_set_options(ssl_ctx,
			    SSL_OP_NO_SSLv2 | SSL_OP_NO_SSLv3
			    | SSL_OP_NO_TLSv1 | SSL_OP_NO_TLSv1_1
			    | SSL_OP_SINGLE_DH_USE
			    | SSL_OP_SINGLE_ECDH_USE
			    | SSL_OP_CIPHER_SERVER_PREFERENCE
			    | SSL_OP_NO_SESSION_RESUMPTION_ON_RENEGOTIATION
			    | SSL_OP_NO_TICKET | SSL_OP_NO_COMPRESSION);

	if (*cipher_list != '\0'
	    && 0 >= SSL_CTX_set_cipher_list(ssl_ctx, cipher_list)) {
		q_pemsg(emsg, "SSL_CTX_set_cipher_list(%s)", cipher_list);
		AXA_ASSERT(__sync_sub_and_fetch(&init_critical, 1) == 0);
		return (false);
	}

	if (!sub_tls_certs_dir(emsg, NULL)) {
		AXA_ASSERT(__sync_sub_and_fetch(&init_critical, 1) == 0);
		return (false);
	}

	AXA_ASSERT(__sync_sub_and_fetch(&init_critical, 1) == 0);
	return (true);
}

bool
axa_apikey_init(axa_emsg_t *emsg, bool srvr, bool threaded)
{
	DSA *dsa;
	DH *dh;
	EC_KEY *ecdh;
	int i;

	/* SSL_library_init() is not reentrant. */
	AXA_ASSERT(__sync_add_and_fetch(&init_critical, 1) == 1);

	/* Do not try to use OpenSSL after releasing it. */
	AXA_ASSERT(apikey_cleaned == false);

	if (apikey_initialized) {
		/* Require consistency. */
		AXA_ASSERT(apikey_srvr == srvr && tls_threaded == threaded);

		/*
		 * Check that every initialization is just as threaded.
		 * No harm is done by using pthread_self() in unthreaded
		 * callers of this, because libaxa uses libnmsg which uses
		 * pthreads.
		 */
		if (!tls_threaded)
			AXA_ASSERT(pthread_self() == apikey_init_id);

		AXA_ASSERT(__sync_sub_and_fetch(&init_critical, 1) == 0);
		return (true);
	}

	apikey_initialized = true;
	apikey_srvr = srvr;
	tls_threaded = threaded;
	apikey_init_id = pthread_self();

	SSL_library_init();
	SSL_load_error_strings();

	OPENSSL_config(NULL);

	/*
	 * Turn on OpenSSL threading if needed.
	 */
	if (tls_threaded) {
		/* static locks */
		CRYPTO_set_id_callback(id_function);
		num_locks = CRYPTO_num_locks();
		if (num_locks != 0) {
			mutex_buf = axa_malloc(num_locks
					       * sizeof(pthread_mutex_t));
			for (i = 0; i < num_locks; i++)
				AXA_ASSERT(0 == pthread_mutex_init(
							&mutex_buf[i],
							NULL));
		}

		CRYPTO_set_locking_callback(locking_function);

		/* dynamic locks */
		CRYPTO_set_dynlock_create_callback(dyn_create_function);
		CRYPTO_set_dynlock_lock_callback(dyn_lock_function);
		CRYPTO_set_dynlock_destroy_callback(dyn_destroy_function);
	}

	ERR_clear_error();

	apikey_ssl_ctx = SSL_CTX_new(SSLv23_method());
	if (apikey_ssl_ctx == NULL) {
		q_pemsg(emsg, "SSL_CTX_new()");
		AXA_ASSERT(__sync_sub_and_fetch(&init_critical, 1) == 0);
		return (false);
	}

	/* Generate DSA parameters for DH because that is faster. */
	RAND_load_file("/dev/urandom", 128);
	dsa = DSA_new();
	if (dsa == NULL) {
		q_pemsg(emsg, "DSA_new()");
		AXA_ASSERT(__sync_sub_and_fetch(&init_critical, 1) == 0);
		return (false);
	}
	if (!DSA_generate_parameters_ex(dsa, 1024, NULL, 0, NULL, NULL, NULL)) {
		q_pemsg(emsg, "DSA_generate_parameters_ex()");
		AXA_ASSERT(__sync_sub_and_fetch(&init_critical, 1) == 0);
		return (false);
	}
	dh = DSA_dup_DH(dsa);
	if (dh == NULL) {
		q_pemsg(emsg, "DSA_dup_DH()");
		DSA_free(dsa);
		AXA_ASSERT(__sync_sub_and_fetch(&init_critical, 1) == 0);
		return (false);
	}
	DSA_free(dsa);
	if (!SSL_CTX_set_tmp_dh(apikey_ssl_ctx, dh)) {
		DH_free(dh);
		q_pemsg(emsg, "SSL_CTX_set_tmp_dh()");
		AXA_ASSERT(__sync_sub_and_fetch(&init_critical, 1) == 0);
		return (false);
	}
	DH_free(dh);

	ecdh = EC_KEY_new_by_curve_name(NID_X9_62_prime256v1);
	if (ecdh == NULL) {
		q_pemsg(emsg,
			  "EC_KEY_new_by_curve_name(NID_X9_62_prime256v1)");
		AXA_ASSERT(__sync_sub_and_fetch(&init_critical, 1) == 0);
		return (false);
	}
	if (SSL_CTX_set_tmp_ecdh(apikey_ssl_ctx, ecdh) != 1) {
		q_pemsg(emsg, "SSL_CTX_set_tmp_ecdh()");
		AXA_ASSERT(__sync_sub_and_fetch(&init_critical, 1) == 0);
		return (false);
	}
	EC_KEY_free(ecdh);

	SSL_CTX_set_mode(apikey_ssl_ctx,
			 SSL_MODE_ENABLE_PARTIAL_WRITE
			 | SSL_MODE_ACCEPT_MOVING_WRITE_BUFFER);

	/*
	 * Is SSL_OP_NO_SSLv2|SSL_OP_NO_SSLv3 needed?
	 */
	SSL_CTX_set_options(apikey_ssl_ctx,
			    SSL_OP_NO_SSLv2 | SSL_OP_NO_SSLv3
			    | SSL_OP_NO_TLSv1 | SSL_OP_NO_TLSv1_1
			    | SSL_OP_SINGLE_DH_USE
			    | SSL_OP_SINGLE_ECDH_USE
			    | SSL_OP_CIPHER_SERVER_PREFERENCE
			    | SSL_OP_NO_SESSION_RESUMPTION_ON_RENEGOTIATION
			    | SSL_OP_NO_TICKET | SSL_OP_NO_COMPRESSION);

	if (*cipher_list != '\0'
	    && 0 >= SSL_CTX_set_cipher_list(apikey_ssl_ctx, cipher_list)) {
		q_pemsg(emsg, "SSL_CTX_set_cipher_list(%s)", cipher_list);
		AXA_ASSERT(__sync_sub_and_fetch(&init_critical, 1) == 0);
		return (false);
	}

	if (!sub_tls_certs_dir(emsg, NULL)) {
		AXA_ASSERT(__sync_sub_and_fetch(&init_critical, 1) == 0);
		return (false);
	}

	AXA_ASSERT(__sync_sub_and_fetch(&init_critical, 1) == 0);
	return (true);
}

void
axa_tls_cleanup(void)
{
	int i;

	/* You cannot restart OpenSSL after shutting it down. */
	if (tls_cleaned)
		return;
	tls_cleaned = true;

	CRYPTO_set_locking_callback(NULL);
	CRYPTO_set_id_callback(NULL);

	CRYPTO_set_dynlock_create_callback(NULL);
	CRYPTO_set_dynlock_lock_callback(NULL);
	CRYPTO_set_dynlock_destroy_callback(NULL);

	CRYPTO_set_locking_callback(NULL);

	if (mutex_buf != NULL) {
		for (i = 0; i < num_locks; i++) {
			pthread_mutex_destroy(&mutex_buf[i]);
		}
		free(mutex_buf);
		mutex_buf = NULL;
	}

	if (ssl_ctx != NULL) {
		SSL_CTX_free(ssl_ctx);
		ssl_ctx = NULL;
	}

	if (certs_dir != NULL) {
		free(certs_dir);
		certs_dir = NULL;
	}

	if (cipher_list != cipher_list0) {
		free(cipher_list);
		cipher_list = cipher_list0;
	}

	ERR_free_strings();
	OPENSSL_no_config();
}

void
axa_apikey_cleanup(void)
{
	int i;

	/* You cannot restart OpenSSL after shutting it down. */
	if (apikey_cleaned)
		return;
	apikey_cleaned = true;

	CRYPTO_set_locking_callback(NULL);
	CRYPTO_set_id_callback(NULL);

	CRYPTO_set_dynlock_create_callback(NULL);
	CRYPTO_set_dynlock_lock_callback(NULL);
	CRYPTO_set_dynlock_destroy_callback(NULL);

	CRYPTO_set_locking_callback(NULL);

	if (mutex_buf != NULL) {
		for (i = 0; i < num_locks; i++) {
			pthread_mutex_destroy(&mutex_buf[i]);
		}
		free(mutex_buf);
		mutex_buf = NULL;
	}

	if (apikey_ssl_ctx != NULL) {
		SSL_CTX_free(apikey_ssl_ctx);
		ssl_ctx = NULL;
	}

	if (cipher_list != cipher_list0) {
		free(cipher_list);
		cipher_list = cipher_list0;
	}

	ERR_free_strings();
	OPENSSL_no_config();
}

/*
 * Parse "certfile,keyfile@host,port" or "user@host,port" for a TLS connection.
 * 	Take everything before the first '@' as the file or user name.
 *	Given "user", assume the file names are user.pem and user.key
 *	User names must not contain '/' or ','.
 *	Look first in the current directory.
 *	If the files are not found in the current directory
 *	and if they do not contain '/', prepend certs_dir and try again.
 */
bool
axa_tls_parse(axa_emsg_t *emsg,
	      char **cert_filep, char **key_filep, char **addrp,
	      const char *spec)
{
	const char *comma, *at;
	struct stat sb;
	char *p;

	AXA_ASSERT(*cert_filep == NULL && *key_filep == NULL && *addrp == NULL);

	/* Just assume we are an un-threaded client
	 * if we have not been told. */
	if (!tls_initialized
	    && !axa_tls_init(emsg, false, false))
		return (false);

	at = strchr(spec, '@');
	comma = strpbrk(spec, ",@");

	if (at == NULL || at == spec) {
		axa_pemsg(emsg, "\"tls:%s\" has no user name or cert files",
			  spec);
		return (false);
	}

	if (comma == at) {
		/* Without a comma, assume we have a user name. */
		axa_asprintf(cert_filep, "%.*s.pem",
			     (int)(comma - spec), spec);
		axa_asprintf(key_filep, "%.*s.key",
			     (int)(comma - spec), spec);
	} else {
		*cert_filep = axa_strndup(spec, comma - spec);
		*key_filep = axa_strndup(comma+1, at - (comma+1));
	}
	*addrp = axa_strdup(at+1);

	/* Try the naked file names. */
	if (0 > stat(*cert_filep, &sb)) {
		axa_pemsg(emsg, "\"%s\" %s: %s",
			  spec, *cert_filep, strerror(errno));
	} else if (0 <= stat(*key_filep, &sb)) {
		return (true);
	} else {
		axa_pemsg(emsg, "\"%s\" %s: %s",
			  spec, *key_filep, strerror(errno));
	}

	/* If that failed,
	 * look in the certs directory if neither file name is a path. */
	if (strchr(*cert_filep, '/') != NULL
	    || strchr(*cert_filep, '/') != NULL)
		return (false);

	axa_asprintf(&p, "%s/%s", certs_dir, *cert_filep);
	free(*cert_filep);
	*cert_filep = p;

	axa_asprintf(&p, "%s/%s", certs_dir, *key_filep);
	free(*key_filep);
	*key_filep = p;

	if (0 > stat(*cert_filep, &sb)) {
		axa_pemsg(emsg, "\"%s\" %s: %s",
			  spec, *cert_filep, strerror(errno));
	} else if (0 <= stat(*key_filep, &sb)) {
		return (true);
	} else {
		axa_pemsg(emsg, "\"%s\" %s: %s",
			  spec, *key_filep, strerror(errno));
	}

	free(*addrp);
	*addrp = NULL;
	free(*cert_filep);
	*cert_filep = NULL;
	free(*key_filep);
	*key_filep = NULL;

	return (false);
}

bool
axa_apikey_parse_srvr(axa_emsg_t *emsg,
	      char **cert_filep, char **key_filep, char **addrp,
	      const char *spec)
{
	const char *comma, *at;
	struct stat sb;
	char *p;

	AXA_ASSERT(*cert_filep == NULL && *key_filep == NULL && *addrp == NULL);

	/* Just assume we are an un-threaded client
	 * if we have not been told. */
	if (!apikey_initialized
	    && !axa_apikey_init(emsg, true, false))
		return (false);

	at = strchr(spec, '@');
	comma = strpbrk(spec, ",@");

	if (at == NULL || at == spec) {
		axa_pemsg(emsg, "\"apikey:%s\" has no apikey or cert files",
			  spec);
		return (false);
	}

	if (comma == at) {
		/* Without a comma, assume we have a user name. */
		axa_asprintf(cert_filep, "%.*s-bundle.crt",
			     (int)(comma - spec), spec);
		axa_asprintf(key_filep, "%.*s.key",
			     (int)(comma - spec), spec);
	} else {
		*cert_filep = axa_strndup(spec, comma - spec);
		*key_filep = axa_strndup(comma+1, at - (comma+1));
	}
	*addrp = axa_strdup(at+1);

	/* Try the naked file names. */
	if (0 > stat(*cert_filep, &sb)) {
		axa_pemsg(emsg, "\"%s\" %s: %s",
			  spec, *cert_filep, strerror(errno));
	} else if (0 <= stat(*key_filep, &sb)) {
		return (true);
	} else {
		axa_pemsg(emsg, "\"%s\" %s: %s",
			  spec, *key_filep, strerror(errno));
	}

	/* If that failed,
	 * look in the certs directory if neither file name is a path. */
	if (strchr(*cert_filep, '/') != NULL
	    || strchr(*cert_filep, '/') != NULL)
		return (false);

	axa_asprintf(&p, "%s/%s", certs_dir, *cert_filep);
	free(*cert_filep);
	*cert_filep = p;

	axa_asprintf(&p, "%s/%s", certs_dir, *key_filep);
	free(*key_filep);
	*key_filep = p;

	if (0 > stat(*cert_filep, &sb)) {
		axa_pemsg(emsg, "\"%s\" %s: %s",
			  spec, *cert_filep, strerror(errno));
	} else if (0 <= stat(*key_filep, &sb)) {
		return (true);
	} else {
		axa_pemsg(emsg, "\"%s\" %s: %s",
			  spec, *key_filep, strerror(errno));
	}

	free(*addrp);
	*addrp = NULL;
	free(*cert_filep);
	*cert_filep = NULL;
	free(*key_filep);
	*key_filep = NULL;

	return (false);
}

/* Initialize per-connection OpenSSL data and complete the TLS handshake. */
axa_io_result_t
axa_tls_start(axa_emsg_t *emsg, axa_io_t *io)
{
	BIO *bio;
	X509 *cert;
	X509_NAME *subject;
	const SSL_CIPHER *cipher;
	const char *comp, *expan;
	int ssl_errno;
	long l;
	int i, j;

	/* Start from scratch the first time. */
	if (io->ssl == NULL) {
		/* Just assume we are an un-threaded client. */
		if (!tls_initialized
		    && !axa_tls_init(emsg, false, false))
			return (AXA_IO_ERR);

		ERR_clear_error();

		io->ssl = SSL_new(ssl_ctx);
		if (io->ssl == NULL) {
			q_pemsg(emsg, "SSL_new()");
			return (AXA_IO_ERR);
		}
		bio = BIO_new_socket(io->i_fd, BIO_NOCLOSE);
		if (bio == NULL) {
			q_pemsg(emsg, "BIO_new_socket()");
			return (AXA_IO_ERR);
		}
		SSL_set_bio(io->ssl, bio, bio);

		if (0 >= SSL_use_PrivateKey_file(io->ssl, io->key_file,
						     SSL_FILETYPE_PEM)) {
			q_pemsg(emsg, "SSL_use_PrivateKey_file(%s)",
				io->key_file);
			return (AXA_IO_ERR);
		}

		if (0 >= SSL_use_certificate_file(io->ssl, io->cert_file,
						  SSL_FILETYPE_PEM)) {
			q_pemsg(emsg, "SSL_use_certificate_file(%s)",
				io->cert_file);
			return (AXA_IO_ERR);
		}

		if (0 >= SSL_check_private_key(io->ssl)) {
			q_pemsg(emsg, "SSL_check_private_key(%s %s)",
				io->cert_file, io->key_file);
			return (AXA_IO_ERR);
		}
	}

	ERR_clear_error();
	if (tls_srvr) {
		ssl_errno = get_ssl_pemsg(emsg, io->ssl, SSL_accept(io->ssl),
					  "SSL_accept()");
	} else {
		ssl_errno = get_ssl_pemsg(emsg, io->ssl, SSL_connect(io->ssl),
					  "SSL_connect()");
	}
	switch (ssl_errno) {
	case SSL_ERROR_NONE:
		break;
	case SSL_ERROR_WANT_READ:
		io->i_events = AXA_POLL_IN;
		io->o_events = 0;
		return (AXA_IO_BUSY);
	case SSL_ERROR_WANT_WRITE:
		io->i_events = AXA_POLL_OUT;
		io->o_events = 0;
		return (AXA_IO_BUSY);
	default:
		return (AXA_IO_ERR);
	}

	/* Require a verified certificate. */
	l = SSL_get_verify_result(io->ssl);
	if (l != X509_V_OK) {
		axa_pemsg(emsg, "verify(): %s",
			  X509_verify_cert_error_string(l));
		return (AXA_IO_ERR);
	}

	/* Get information about the connection and the peer. */
	AXA_ASSERT(io->tls_info == NULL);
	comp = "no compression";
	expan = "no compression";

	cipher = SSL_get_current_cipher(io->ssl);
	axa_asprintf(&io->tls_info, "%s %s  %s%s%s",
		     SSL_CIPHER_get_version(cipher),
		     SSL_CIPHER_get_name(cipher),
		     comp,
		     expan != comp ? "/" : "",
		     expan != comp ? expan : "");


	/*
	 * Use the subject common name (CN) as the peer user name.
	 */
	cert = SSL_get_peer_certificate(io->ssl);
	/* SSL_get_verify_result() == X509_V_OK guarantees the certificate. */
	AXA_ASSERT(cert != NULL);
	subject = X509_get_subject_name(cert);
	if (subject == NULL) {
		/* Is this possible? */
		X509_free(cert);
		axa_pemsg(emsg, "invalid null certificate subject");
		return (AXA_IO_ERR);
	}
	i = X509_NAME_get_text_by_NID(subject, NID_commonName, NULL, 0);
	if (i < 0) {
		X509_free(cert);
		axa_pemsg(emsg, "cannot find certificate CN");
		return (AXA_IO_ERR);
	}
	if ((size_t)i > sizeof(io->user.name)) {
		X509_free(cert);
		axa_pemsg(emsg, "certificate CN length of %d is too long", i);
		return (AXA_IO_ERR);
	}
	j = X509_NAME_get_text_by_NID(subject, NID_commonName,
				      io->user.name, sizeof(io->user.name));
	AXA_ASSERT(i == j);
	X509_free(cert);

	/* The TLS handshaking is finished. */
	io->i_events = AXA_POLL_IN;
	io->o_events = 0;

	io->connected = true;
	return (AXA_IO_OK);
}

/* Initialize per-connection OpenSSL data and complete the TLS handshake. */
axa_io_result_t
axa_apikey_start(axa_emsg_t *emsg, axa_io_t *io)
{
	BIO *bio;
	const SSL_CIPHER *cipher;
	const char *comp, *expan;
	int ssl_errno;

	/* Start from scratch the first time. */
	if (io->ssl == NULL) {
		/* Just assume we are an un-threaded client. */
		if (!apikey_initialized
		    && !axa_apikey_init(emsg, false, false))
			return (AXA_IO_ERR);

		ERR_clear_error();

		if (apikey_srvr) {
			if (0 >= SSL_CTX_use_PrivateKey_file(apikey_ssl_ctx,
						io->key_file,
						SSL_FILETYPE_PEM)) {
				q_pemsg(emsg, "SSL_use_PrivateKey_file(%s)",
					io->key_file);
				return (AXA_IO_ERR);
			}

			if (0 >= SSL_CTX_use_certificate_chain_file(
						apikey_ssl_ctx,
						io->cert_file)) {
				q_pemsg(emsg,
				"SSL_CTX_use_certificate_chain_file(%s)",
				io->cert_file);
				return (AXA_IO_ERR);
			}

			if (0 >= SSL_CTX_check_private_key(apikey_ssl_ctx)) {
				q_pemsg(emsg, "SSL_check_private_key(%s %s)",
					io->cert_file, io->key_file);
				return (AXA_IO_ERR);
			}
		}
		io->ssl = SSL_new(apikey_ssl_ctx);
		if (io->ssl == NULL) {
			q_pemsg(emsg, "SSL_new()");
			return (AXA_IO_ERR);
		}
		bio = BIO_new_socket(io->i_fd, BIO_NOCLOSE);
		if (bio == NULL) {
			q_pemsg(emsg, "BIO_new_socket()");
			return (AXA_IO_ERR);
		}
		SSL_set_bio(io->ssl, bio, bio);

	}

	ERR_clear_error();
	if (apikey_srvr) {
		ssl_errno = get_ssl_pemsg(emsg, io->ssl, SSL_accept(io->ssl),
					  "SSL_accept()");
	} else {
		ssl_errno = get_ssl_pemsg(emsg, io->ssl, SSL_connect(io->ssl),
					  "SSL_connect()");
	}
	switch (ssl_errno) {
	case SSL_ERROR_NONE:
		break;
	case SSL_ERROR_WANT_READ:
		io->i_events = AXA_POLL_IN;
		io->o_events = 0;
		return (AXA_IO_BUSY);
	case SSL_ERROR_WANT_WRITE:
		io->i_events = AXA_POLL_OUT;
		io->o_events = 0;
		return (AXA_IO_BUSY);
	default:
		return (AXA_IO_ERR);
	}

	/* Get information about the connection and the peer. */
	AXA_ASSERT(io->tls_info == NULL);
	comp = "no compression";
	expan = "no compression";

	cipher = SSL_get_current_cipher(io->ssl);
	axa_asprintf(&io->tls_info, "%s %s  %s%s%s",
		     SSL_CIPHER_get_version(cipher),
		     SSL_CIPHER_get_name(cipher),
		     comp,
		     expan != comp ? "/" : "",
		     expan != comp ? expan : "");

	/* The TLS handshaking is finished. */
	io->i_events = AXA_POLL_IN;
	io->o_events = 0;

	io->connected = true;
	return (AXA_IO_OK);
}

/* Close and release per-connection OpenSSL data */
void
axa_tls_stop(axa_io_t *io)
{
	if (io->ssl != NULL) {
		SSL_free(io->ssl);
		io->ssl = NULL;
	}
}

void
axa_apikey_stop(axa_io_t *io)
{
	if (io->ssl != NULL) {
		SSL_free(io->ssl);
		io->ssl = NULL;
	}
}

/* TLS input */
axa_io_result_t
axa_tls_read(axa_emsg_t *emsg, axa_io_t *io)
{
	int ret, ssl_errno;

	AXA_ASSERT(io->i_events != 0);

	ERR_clear_error();
	ret = SSL_read(io->ssl, io->recv_buf, io->recv_buf_len);
	ssl_errno = get_ssl_pemsg(emsg, io->ssl, ret,
				  "SSL_read(%d)", io->recv_buf_len);
	switch (ssl_errno) {
	case SSL_ERROR_NONE:
		break;
	case SSL_ERROR_WANT_READ:
		io->i_events = AXA_POLL_IN;
		return (AXA_IO_BUSY);
	case SSL_ERROR_WANT_WRITE:
		io->i_events = AXA_POLL_OUT;
		return (AXA_IO_BUSY);
	default:
		io->i_events = 0;
		return (AXA_IO_ERR);
	}

	io->recv_bytes = ret;
	gettimeofday(&io->alive, NULL);

	io->i_events = AXA_POLL_IN;
	return (AXA_IO_OK);
}

/* TLS output */
axa_io_result_t
axa_tls_flush(axa_emsg_t *emsg, axa_io_t *io)
{
	int ret, ssl_errno;

	for (;;) {
		ERR_clear_error();
		ret = SSL_write(io->ssl, io->send_start, io->send_bytes);
		ssl_errno = get_ssl_pemsg(emsg, io->ssl, ret,
				"SSL_write(%d)", io->send_bytes);
		switch (ssl_errno) {
			 case SSL_ERROR_NONE:
				 break;
			 case SSL_ERROR_WANT_READ:
				 io->o_events = AXA_POLL_IN;
				 return (AXA_IO_BUSY);
			 case SSL_ERROR_WANT_WRITE:
				 io->o_events = AXA_POLL_OUT;
				 return (AXA_IO_BUSY);
			 default:
				 io->o_events = 0;
				 return (AXA_IO_ERR);
		}

		AXA_ASSERT(io->send_bytes >= (size_t)ret);
		io->send_start += ret;
		io->send_bytes -= ret;
		if (io->send_bytes != 0)
			continue;

		io->o_events = 0;
		gettimeofday(&io->alive, NULL);
		return (AXA_IO_OK);
	}
}
