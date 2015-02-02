/*
 * TLS transport
 *
 *  Copyright (c) 2015 by Farsight Security, Inc.
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


static char certs_dir0[] = AXACONFDIR"/certs";
static char *certs_dir = certs_dir0;

const char *axa_tls_ciphers = TLS_CIPHERS;

static SSL_CTX *ssl_ctx;


#ifndef OPENSSL_THREADS
#error "this installation of OpenSSL lacks thread support"
#endif
struct CRYPTO_dynlock_value {
	pthread_mutex_t mutex;
};

static pthread_mutex_t *mutex_buf = NULL;



static void AXA_PF(3,4)
ssl_pemsg(axa_emsg_t *emsg, unsigned long ssl_err, const char *p, ...)
{
	const char *str;
	char *msg;
	va_list args;

	va_start(args, p);
	axa_vasprintf(&msg, p, args);
	va_end(args);

	ssl_err = ERR_get_error();
	str = ERR_reason_error_string(ssl_err);
	if (str != NULL) {
		axa_pemsg(emsg, "%s: %s", msg, str);
	} else {
		axa_pemsg(emsg, "%s failed: error=%lu", msg, ssl_err);
	}
	free(msg);
}

/* Thread ID callback for OpenSSL */
static unsigned long
id_function(void)
{
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wbad-function-cast"
	/* pthread_t is a pointer on some systems including FreeBSD */
	return ((unsigned long)pthread_self());
#pragma clang diagnostic pop
}

/* Lock or unlock a static (created at initialization) lock for OpenSSL */
static void
locking_function(int mode, int n,
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
dyn_create_function(const char *file AXA_UNUSED, int line AXA_UNUSED)
{
	struct CRYPTO_dynlock_value *value;

	value = (struct CRYPTO_dynlock_value *)
	axa_malloc(sizeof(struct CRYPTO_dynlock_value));
	AXA_ASSERT(0 == pthread_mutex_init(&value->mutex, NULL));
	return value;
}

/* Destroy a "dynamic" lock for OpenSSL */
static void
dyn_destroy_function(struct CRYPTO_dynlock_value *l,
		     const char *file AXA_UNUSED, int line AXA_UNUSED)
{
	AXA_ASSERT(0 == pthread_mutex_destroy(&l->mutex));
	free(l);
}

/* Lock or unlock a "dynamic" lock */
static void
dyn_lock_function(int mode, struct CRYPTO_dynlock_value *l,
		  const char *file AXA_UNUSED, int line AXA_UNUSED)
{
	if (mode & CRYPTO_LOCK) {
		AXA_ASSERT(0 == pthread_mutex_lock(&l->mutex));
	} else {
		AXA_ASSERT(0 == pthread_mutex_unlock(&l->mutex));
	}
}

static bool
ck_certs_dir(axa_emsg_t *emsg, const char *dir)
{
	struct stat sb;

	if (0 > stat(dir, &sb)) {
		axa_pemsg(emsg, "certificate directory %s: %s",
			  dir, strerror(errno));
		return (false);
	}

	if (!S_ISDIR(sb.st_mode)) {
		axa_pemsg(emsg, "%s is not a certificate directory", dir);
		return (false);
	}

	if (0 > eaccess(dir, X_OK)) {
		axa_pemsg(emsg, "certificate %s directory: %s",
			  dir, strerror(errno));
		return (false);
	}

	return (true);
}

bool
axa_tls_certs_dir(axa_emsg_t *emsg, const char *dir)
{
	if (!ck_certs_dir(emsg, dir))
		return (false);

	if (certs_dir != certs_dir0) {
		free(certs_dir);
		certs_dir = certs_dir0;
	}
	certs_dir = axa_strdup(dir);
	return (true);
}

static bool
axa_tls_init(axa_emsg_t *emsg, bool srvr)
{
	DSA *dsa;
	DH *dh;
	EC_KEY *ecdh;
	int i;

	if (mutex_buf != NULL)
		return (true);

	SSL_library_init();
	SSL_load_error_strings();

	OPENSSL_config(NULL);

	/* static locks */
	mutex_buf = axa_malloc(CRYPTO_num_locks() * sizeof(pthread_mutex_t));
	for (i = 0; i < CRYPTO_num_locks(); i++)
		AXA_ASSERT(0 == pthread_mutex_init(&mutex_buf[i], NULL));

	CRYPTO_set_id_callback(id_function);
	CRYPTO_set_locking_callback(locking_function);

	/* dynamic locks */
	CRYPTO_set_dynlock_create_callback(dyn_create_function);
	CRYPTO_set_dynlock_lock_callback(dyn_lock_function);
	CRYPTO_set_dynlock_destroy_callback(dyn_destroy_function);

	SSL_load_error_strings();

#ifndef OPENSSL_NO_COMP
	if (0 != SSL_COMP_add_compression_method(1, COMP_zlib())) {
		ssl_pemsg(emsg, ERR_get_error(), "SSL_CTX_new()");
		return (false);
	}
#endif

	ssl_ctx = SSL_CTX_new(SSLv23_method());
	if (ssl_ctx == NULL) {
		ssl_pemsg(emsg, ERR_get_error(), "SSL_CTX_new()");
		return (false);
	}

	/* Generate DSA parameters for DH because that is faster. */
	RAND_load_file("/dev/urandom", 128);
	dsa = DSA_new();
	if (dsa == NULL) {
		ssl_pemsg(emsg, ERR_get_error(), "DSA_new()");
		return (false);
	}
	if (!DSA_generate_parameters_ex(dsa, 1024, NULL, 0,
					NULL, NULL, NULL)) {
		ssl_pemsg(emsg, ERR_get_error(),
			  "DSA_generate_parameters_ex()");
		return (false);
	}
	dh = DSA_dup_DH(dsa);
	if (dh == NULL) {
		ssl_pemsg(emsg, ERR_get_error(), "DSA_dup_DH()");
		DSA_free(dsa);
		return (false);
	}
	DSA_free(dsa);
	if (!SSL_CTX_set_tmp_dh(ssl_ctx, dh)) {
		DH_free(dh);
		ssl_pemsg(emsg, ERR_get_error(), "SSL_CTX_set_tmp_dh()");
		return (false);
	}
	DH_free(dh);

	ecdh = EC_KEY_new_by_curve_name(NID_X9_62_prime256v1);
	if (ecdh == NULL) {
		ssl_pemsg(emsg, ERR_get_error(),
			  "EC_KEY_new_by_curve_name(NID_X9_62_prime256v1)");
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
	 * No SSL_OP_NO_COMPRESSION because CRIME does not apply.
	 * Is SSL_OP_NO_SSLv2|SSL_OP_NO_SSLv3 needed?
	 */
	SSL_CTX_set_options(ssl_ctx,
			    SSL_OP_NO_SSLv2 | SSL_OP_NO_SSLv3
			    | SSL_OP_NO_TLSv1 | SSL_OP_NO_TLSv1_1
			    | SSL_OP_SINGLE_DH_USE
			    | SSL_OP_SINGLE_ECDH_USE
			    | SSL_OP_CIPHER_SERVER_PREFERENCE
			    | SSL_OP_NO_SESSION_RESUMPTION_ON_RENEGOTIATION
			    | SSL_OP_NO_TICKET);

	if (0 >= SSL_CTX_set_cipher_list(ssl_ctx, axa_tls_ciphers)) {
		ssl_pemsg(emsg, ERR_get_error(), "SSL_CTX_set_cipher_list(%s)",
			  axa_tls_ciphers);
		return (false);
	}

	if (0 >= SSL_CTX_load_verify_locations(ssl_ctx, NULL, certs_dir)) {
		ssl_pemsg(emsg, ERR_get_error(),
			  "SSL_CTX_load_verify_locations(%s)", certs_dir);
		return (false);
	}

	return (true);
}

void
axa_tls_cleanup(void)
{
	int i;

	CRYPTO_set_locking_callback(NULL);
	CRYPTO_set_id_callback(NULL);

	CRYPTO_set_dynlock_create_callback(NULL);
	CRYPTO_set_dynlock_lock_callback(NULL);
	CRYPTO_set_dynlock_destroy_callback(NULL);

	CRYPTO_set_locking_callback(NULL);

	if (mutex_buf != NULL) {
		for (i = 0; i < CRYPTO_num_locks(); i++) {
			pthread_mutex_destroy(&mutex_buf[i]);
		}
		free(mutex_buf);
		mutex_buf = NULL;
	}

	if (ssl_ctx != NULL) {
		SSL_CTX_free(ssl_ctx);
		ssl_ctx = NULL;
	}

	if (certs_dir != certs_dir0) {
		free(certs_dir);
		certs_dir = certs_dir0;
	}
}

static bool
try_alt(char **cert_filep, char **key_filep,
	const char *dir, const char *slash, const char *pem)
{
	char *cert_file, *key_file;
	struct stat sb;

	axa_asprintf(&cert_file, "%s%s%s%s", dir, slash, *cert_filep, pem);
	axa_asprintf(&key_file, "%s%s%s%s", dir, slash, *key_filep, pem);
	if (0 <= stat(cert_file, &sb) && 0 <= stat(key_file, &sb)) {
		free(*cert_filep);
		*cert_filep = cert_file;
		free(*key_filep);
		*key_filep = key_file;
		return (true);
	}

	free(cert_file);
	free(key_file);
	return (false);
}

/*
 * Parse "certfile,keyfile@host,port" for a TLS connection.
 * Do not allow '@' or ',' in the file or directory names.
 */
bool
axa_tls_parse(axa_emsg_t *emsg,
	      char **cert_filep, char **key_filep, char **addrp,
	      const char *spec)
{
	char *key_file, *addr, *file;
	int file_errno;
	struct stat sb;
#	define EMSG "\"tls:%s\" is not \"tls:cert_file,key_file@user,port\""

	if (!ck_certs_dir(emsg, certs_dir))
		return (false);

	key_file = strchr(spec, ',');
	if (key_file == NULL || key_file == spec) {
		axa_pemsg(emsg, EMSG, spec);
		return (false);
	}
	++key_file;

	addr = strchr(spec, '@');
	if (addr == NULL) {
		axa_pemsg(emsg, EMSG, spec);
		return (false);
	}
	if (addr == key_file) {
		axa_pemsg(emsg, EMSG, spec);
		return (false);
	}

	*addrp = axa_strdup(addr+1);
	*cert_filep = axa_strndup(spec, key_file - spec - 1);
	*key_filep = axa_strndup(key_file, addr - key_file);

	if (0 > stat(*cert_filep, &sb)) {
		file = *cert_filep;
		file_errno = errno;
	} else if (0 > stat(*key_filep, &sb)) {
		file = *key_filep;
		file_errno = errno;
	} else {
		return (true);
	}

	/* Look for the files in the directory and with ".pem". */
	if (try_alt(cert_filep, key_filep, "", "", ".pem"))
		return (true);
	if (**cert_filep == '/' || **key_filep == '/')
		return (false);
	if (try_alt(cert_filep, key_filep, certs_dir, "/", ""))
		return (true);
	if (try_alt(cert_filep, key_filep, certs_dir, "/", ".pem"))
		return (true);

	axa_pemsg(emsg, "\"%s\" %s: %s", spec, file, strerror(file_errno));
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
axa_tls_start(axa_emsg_t *emsg, axa_io_t *io, bool srvr)
{
	BIO *bio;
	X509 *cert;
	X509_NAME *subject;
	const char *label;
	const SSL_CIPHER *cipher;
	const char *comp, *expan;
	unsigned long ssl_err;
	long l;
	int i, j;

	/* Start from scratch the first time. */
	if (io->ssl == NULL) {
		if (!axa_tls_init(emsg, srvr))
			return (AXA_IO_ERR);

		io->ssl = SSL_new(ssl_ctx);
		if (io->ssl == NULL) {
			ssl_pemsg(emsg, ERR_get_error(), "SSL_new()");
			return (AXA_IO_ERR);
		}
		bio = BIO_new_socket(io->i_fd, BIO_NOCLOSE);
		if (bio == NULL) {
			ssl_pemsg(emsg, ERR_get_error(), "BIO_new_socket()");
			return (AXA_IO_ERR);
		}
		SSL_set_bio(io->ssl, bio, bio);

		if (0 >= SSL_use_PrivateKey_file(io->ssl, io->key_file,
						     SSL_FILETYPE_PEM)) {
			ssl_pemsg(emsg, ERR_get_error(),
				  "SSL_use_PrivateKey_file(%s)", io->key_file);
			return (AXA_IO_ERR);
		}

		if (0 >= SSL_use_certificate_file(io->ssl, io->cert_file,
						  SSL_FILETYPE_PEM)) {
			ssl_pemsg(emsg, ERR_get_error(),
				  "SSL_use_certificate_file(%s)", io->cert_file);
			return (AXA_IO_ERR);
		}

		if (0 >= SSL_check_private_key(io->ssl)) {
			ssl_pemsg(emsg, ERR_get_error(),
				  "SSL_check_private_key(%s %s)",
				  io->cert_file, io->key_file);
			return (AXA_IO_ERR);
		}
	}

	if (srvr) {
		label = "SSL_accept()";
		i = SSL_accept(io->ssl);
	} else {
		label = "SSL_connect()";
		i = SSL_connect(io->ssl);
	}
	if (i <= 0) {
		ssl_err = SSL_get_error(io->ssl, i);

		if (i == 0) {
			ssl_pemsg(emsg, ssl_err, "%s", label);
			return (AXA_IO_ERR);
		}

		switch (ssl_err) {
		case SSL_ERROR_WANT_READ:
			io->i_events = AXA_POLL_IN;
			io->o_events = 0;
			return (AXA_IO_BUSY);
		case SSL_ERROR_WANT_WRITE:
			io->i_events = AXA_POLL_OUT;
			io->o_events = 0;
			return (AXA_IO_BUSY);
		default:
			ssl_pemsg(emsg, ssl_err, "%s", label);
			return (AXA_IO_ERR);
		}
	}
	io->i_events = AXA_POLL_IN;
	io->o_events = 0;

	/*
	 * Require a verified certificate.
	 * This might be redundant given SSL_VERIFY_FAIL_IF_NO_PEER_CERT.
	 */
	l = SSL_get_verify_result(io->ssl);
	if (l != X509_V_OK) {
		axa_pemsg(emsg, "verify(): %s",
			  X509_verify_cert_error_string(l));
		return (AXA_IO_ERR);
	}

	AXA_ASSERT(io->tls_info == NULL);
	comp = SSL_COMP_get_name(SSL_get_current_compression(io->ssl));
	if (comp == NULL)
		comp = "no compression";
	expan = SSL_COMP_get_name(SSL_get_current_expansion(io->ssl));
	if (expan == NULL)
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

/* TLS output */
axa_io_result_t
axa_tls_flush(axa_emsg_t *emsg, axa_io_t *io)
{
	unsigned long ssl_err;
	int i;

	i = SSL_write(io->ssl, io->send_start, io->send_bytes);
	if (i <= 0) {
		ssl_err = ERR_get_error();
		switch (ssl_err) {
		case SSL_ERROR_WANT_READ:
			io->o_events = AXA_POLL_IN;
			return (AXA_IO_BUSY);
		case SSL_ERROR_WANT_WRITE:
			io->o_events = AXA_POLL_OUT;
			return (AXA_IO_BUSY);
		default:
			io->o_events = 0;
			ssl_pemsg(emsg, ssl_err, "%s", "SSL_write()");
			return (AXA_IO_ERR);
		}
	}

	AXA_ASSERT(io->send_bytes >= (size_t)i);
	io->send_start += i;
	io->send_bytes -= i;
	if (io->send_bytes != 0)
		io->o_events = AXA_POLL_OUT;
	else
		io->o_events = 0;

	gettimeofday(&io->alive, NULL);

	return (AXA_IO_OK);
}

/* TLS input */
axa_io_result_t
axa_tls_read(axa_emsg_t *emsg, axa_io_t *io)
{
	unsigned long ssl_err;
	int i;

	AXA_ASSERT(io->i_events != 0);

	i = SSL_read(io->ssl, io->recv_buf, io->recv_buf_len);
	if (i <=0) {
		ssl_err = ERR_get_error();
		switch (ssl_err) {
		case SSL_ERROR_WANT_READ:
			io->i_events = AXA_POLL_IN;
			return (AXA_IO_BUSY);
		case SSL_ERROR_WANT_WRITE:
			io->i_events = AXA_POLL_OUT;
			return (AXA_IO_BUSY);
		default:
			io->i_events = 0;
			ssl_pemsg(emsg, ssl_err, "%s", "SSL_read()");
			return (AXA_IO_ERR);
		}
	}

	io->recv_bytes = i;
	gettimeofday(&io->alive, NULL);

	io->i_events = AXA_POLL_IN;
	return (AXA_IO_OK);
}
