/*
 * radd, radtool, and sratool common client code
 *
 *  Copyright (c) 2014-2018 by Farsight Security, Inc.
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

#include <axa/client.h>
#include <axa/socket.h>
#include <axa/strbuf.h>
#include <axa/json.h>
#include <axa/yajl_shortcuts.h>

#include <libmy/ubuf-pb.h>		/* query protobuf version */

#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdlib.h>
#include <string.h>
#ifdef __linux
#include <bsd/string.h>			/* for strlcpy() */
#endif
#include <sysexits.h>
#include <sys/utsname.h>
#include <unistd.h>
#include <wdns.h>

#include <yajl/yajl_version.h>
#include <yajl/yajl_gen.h>

#define	MIN_BACKOFF_MS	(1*1000)
#define	MAX_BACKOFF_MS	(60*1000)

#ifndef HOST_NAME_MAX
#define HOST_NAME_MAX 255
#endif

void
axa_client_init(axa_client_t *client)
{
	time_t backoff;
	struct timeval retry;

	/* Do not change the back-off clock. */
	backoff = client->backoff;
	retry = client->retry;

	memset(client, 0, sizeof(*client));
	axa_io_init(&client->io);

	client->retry = retry;
	client->backoff = backoff;
}

void
axa_client_backoff(axa_client_t *client)
{
	axa_client_close(client);

	gettimeofday(&client->retry, NULL);
	client->backoff = max(MIN_BACKOFF_MS, client->backoff*2);
	if (client->backoff > MAX_BACKOFF_MS)
		client->backoff = MAX_BACKOFF_MS;
}

void
axa_client_backoff_max(axa_client_t *client)
{
	axa_client_close(client);

	gettimeofday(&client->retry, NULL);
	client->backoff = MAX_BACKOFF_MS;
}

void
axa_client_backoff_reset(axa_client_t *client)
{
	client->retry.tv_sec = 0;
	client->backoff = 0;
}

time_t					/* ms until retry or < 0 */
axa_client_again(axa_client_t *client, struct timeval *now)
{
	struct timeval tv;

	if (client->retry.tv_sec == 0)
		return (-1);

	if (now == NULL)
		now = &tv;
	gettimeofday(now, NULL);

	return (client->backoff - axa_elapsed_ms(now, &client->retry));
}

void
axa_client_close(axa_client_t *client)
{
	/* Everything except the reconnection timers must be set again
	 * if and when it is re-opened. */

	axa_io_close(&client->io);

	if (client->hello != NULL) {
		free(client->hello);
		client->hello = NULL;
	}

	client->have_id = false;
	client->clnt_id = 0;
}

static bool
connect_ssh(axa_emsg_t *emsg, axa_client_t *client,
	    bool nonblock, bool ssh_debug)
{
	int in_fildes[2], out_fildes[2], err_fildes[2];

	if (0 > pipe(in_fildes)) {
		axa_pemsg(emsg, "pipe(%s): %s",
			  client->io.label, strerror(errno));
		return (false);
	}
	if (0 > pipe(out_fildes)) {
		axa_pemsg(emsg, "pipe(%s): %s",
			  client->io.label, strerror(errno));
		close(in_fildes[0]);
		close(in_fildes[1]);
		return (false);
	}
	if (0 > pipe(err_fildes)) {
		axa_pemsg(emsg, "pipe(%s): %s",
			  client->io.label, strerror(errno));
		close(in_fildes[0]);
		close(in_fildes[1]);
		close(out_fildes[0]);
		close(out_fildes[1]);
		return (false);
	}
	client->io.tun_pid = fork();
	if (client->io.tun_pid == -1) {
		axa_pemsg(emsg, "ssh fork(%s): %s",
			  client->io.label, strerror(errno));
		close(in_fildes[0]);
		close(in_fildes[1]);
		close(out_fildes[0]);
		close(out_fildes[1]);
		close(err_fildes[0]);
		close(err_fildes[1]);
		return (false);
	}
	if (client->io.tun_pid == 0) {
		/* Run ssh in the child process. */
		signal(SIGPIPE, SIG_IGN);
		signal(SIGHUP, SIG_IGN);
		signal(SIGTERM, SIG_IGN);
		signal(SIGINT, SIG_IGN);
#ifdef SIGXFSZ
		signal(SIGXFSZ, SIG_IGN);
#endif

		if (0 > dup2(in_fildes[1], STDOUT_FILENO)
		    || 0 > dup2(out_fildes[0], STDIN_FILENO)
		    || 0 > dup2(err_fildes[1], STDERR_FILENO)) {
			axa_error_msg("ssh dup2(%s): %s",
				      client->io.label, strerror(errno));
			exit(EX_OSERR);
		}
		close(in_fildes[0]);
		close(out_fildes[1]);
		close(err_fildes[0]);

		/*
		 * -v	only when debugging is enabled
		 * -T	no pseudo-tty
		 * -a	disable forwarding of the authentication agent
		 *	    connection
		 * -x	no X11 forwarding
		 * -oBatchMode=yes  no interactive passphrase/password querying
		 * -oStrictHostKeyChecking=no do not look for the server's key
		 *	    in the known_hosts file and so do not worry about
		 *	    men in the middle to prevent user interaction when
		 *	    the server's key changes
		 * -oCheckHostIP=no do not check for the server's IP address
		 *	    in the known_hosts file
		 * -enone for no escape character because we are moving binary
		 */
		if (ssh_debug)
			execlp("ssh", "ssh", "-v",
			       "-Tax", "-oBatchMode=yes",
			       "-oStrictHostKeyChecking=no",
			       "-oCheckHostIP=no",
			       "-enone",
			       client->io.addr, NULL);
		else
			execlp("ssh", "ssh",
			       "-Tax", "-oBatchMode=yes",
			       "-oStrictHostKeyChecking=no",
			       "-oCheckHostIP=no",
			       "-enone",
			       client->io.addr, NULL);
		axa_error_msg("exec(ssh %s): %s",
			      client->io.addr, strerror(errno));
		exit(EX_OSERR);
	}

	/* Finish setting up links to the ssh child in this the parent. */
	client->io.i_fd = in_fildes[0];
	client->io.i_events = AXA_POLL_IN;
	client->io.o_fd = out_fildes[1];
	client->io.o_events = 0;
	client->io.tun_fd = err_fildes[0];
	close(in_fildes[1]);
	close(out_fildes[0]);
	close(err_fildes[1]);

	if (!axa_set_sock(emsg, client->io.i_fd, client->io.label,
			  0, nonblock)
	    || !axa_set_sock(emsg, client->io.o_fd, client->io.label,
			     0, nonblock)
	    || !axa_set_sock(emsg, client->io.tun_fd, client->io.label,
			     0, true))  {
		return (false);
	}

	return (true);
}

static axa_connect_result_t
socket_connect(axa_emsg_t *emsg, axa_client_t *client)
{
	int i;

	if (!AXA_CLIENT_OPENED(client)) {
		client->io.o_fd = socket(client->io.su.sa.sa_family,
					 SOCK_STREAM, 0);
		if (client->io.o_fd < 0) {
			axa_pemsg(emsg, "socket(%s): %s",
				  client->io.label, strerror(errno));
			axa_client_backoff_max(client);
			return (AXA_CONNECT_ERR);
		}
		client->io.i_fd = client->io.o_fd;

		if (!axa_set_sock(emsg, client->io.o_fd, client->io.label,
				  client->io.bufsize, client->io.nonblock))  {
			axa_client_backoff_max(client);
			return (AXA_CONNECT_ERR);
		}
	}

	if (!client->io.connected_tcp) {
		i = connect(client->io.o_fd, &client->io.su.sa,
			    AXA_SU_LEN(&client->io.su));
		if (0 <= i || errno == EISCONN) {
			/* We finished a new connection or a previously
			 * started non-blocking connection. */
			client->io.connected_tcp = true;
			client->io.i_events = AXA_POLL_IN;
			client->io.o_events = 0;

		} else if (client->io.nonblock && AXA_CONN_WAIT_ERRORS()) {
			/* Non-blocking connection unfinished. */
			client->io.i_events = AXA_POLL_OUT;
			client->io.o_events = 0;
			return (AXA_CONNECT_INCOM);

		} else {
			/* Failed to connect. */
			axa_pemsg(emsg, "connect(%s): %s",
				  client->io.label, strerror(errno));
			axa_client_backoff(client);
			return (AXA_CONNECT_TEMP);
		}
	}

	return (AXA_CONNECT_DONE);
}

axa_connect_result_t
axa_client_connect(axa_emsg_t *emsg, axa_client_t *client)
{
	axa_p_hdr_t hdr;
	axa_connect_result_t connect_result;
	uint8_t pvers_save;

	if (AXA_CLIENT_CONNECTED(client))
		return (AXA_CONNECT_DONE);

	/* Clamp the AXA protocol version to 1 (guaranteed to be spoken by all
	 * AXA clients and servers. This is done just before the identification
	 * and authentication (I&A) message exchange and subsequent  spin-up of
	 * the encrypted tunnel. We do this for two reasons:
	 *
	 * 1. A client's preferred AXA protocol version (AXA_PVERS) may be
	 *    higher than what the server can understand (such would be the
	 *    case when a newer client connects to an older server).
	 * 2. AXA protocol version negotiation is performed during the HELLO
	 *    handshake. This happens after I&A, allowing it to be
	 *    performed inside an encrypted tunnel and prevent information
	 *    leakage to an observer. The issue is the I&A process involves the
	 *    exchange of AXA messages (AXA_P_OP_USER and/or AXA_P_OP_NOP). If
	 *    the AXA protocol version were too new, the server wouldn't
	 *    understand (but also wouldn't have had the option to tell the
	 *    client to downgrade its AXA protocol version).
	 *
	 *    The downside here is that the AXA I&A message exchange protocol
	 *    cannot change. New I&A methods can be added or removed but the
	 *    structure of the messages must remain the same.
	 *
	 *    After I&A, the AXA protocol may be set to a version the client
	 *    prefers, and the HELLO handshake should proceed.
	 */
	axa_io_pvers_get(&client->io, &pvers_save);
	axa_io_pvers_set(&client->io, AXA_P_PVERS1);

	switch (client->io.type) {
	case AXA_IO_TYPE_UNIX:
	case AXA_IO_TYPE_TCP:
		connect_result = socket_connect(emsg, client);
		if (connect_result != AXA_CONNECT_DONE) {
			axa_io_pvers_set(&client->io, pvers_save);
			return (connect_result);
		}
		client->io.connected = true;

		/* TCP and UNIX domain sockets need a user name */
		if (client->io.user.name[0] != '\0') {
			if (!axa_client_send(emsg, client,
					     AXA_TAG_NONE, AXA_P_OP_USER, &hdr,
					     &client->io.user,
					     sizeof(client->io.user))) {
				axa_client_backoff(client);
				axa_io_pvers_set(&client->io, pvers_save);
				return (AXA_CONNECT_ERR);
			}
			axa_p_to_str(emsg->c, sizeof(emsg->c),
				     true, &hdr,
				     (axa_p_body_t *)&client->io.user);
			axa_io_pvers_set(&client->io, pvers_save);
			return (AXA_CONNECT_USER);
		}
		break;

	case AXA_IO_TYPE_SSH:
		if (!AXA_CLIENT_OPENED(client)) {
			if (!connect_ssh(emsg, client, client->io.nonblock,
					 client->io.tun_debug)) {
				axa_client_backoff_max(client);
				axa_io_pvers_set(&client->io, pvers_save);
				return (AXA_CONNECT_ERR);
			}
			client->io.connected_tcp = true;
			client->io.connected = true;
		}
		break;

	case AXA_IO_TYPE_TLS:
		connect_result = socket_connect(emsg, client);
		if (connect_result != AXA_CONNECT_DONE) {
			axa_io_pvers_set(&client->io, pvers_save);
			return (connect_result);
		}
		switch (axa_tls_start(emsg, &client->io)) {
		case AXA_IO_OK:
			break;
		case AXA_IO_ERR:
			axa_client_backoff_max(client);
			axa_io_pvers_set(&client->io, pvers_save);
			return (AXA_CONNECT_ERR);
		case AXA_IO_BUSY:
			AXA_ASSERT(client->io.nonblock);
			axa_io_pvers_set(&client->io, pvers_save);
			return (connect_result);
		case AXA_IO_TUNERR:
		case AXA_IO_KEEPALIVE:
			AXA_FAIL("impossible axa_tls_start() result");
		}
		break;

	case AXA_IO_TYPE_APIKEY:
		connect_result = socket_connect(emsg, client);
		if (connect_result != AXA_CONNECT_DONE) {
			axa_io_pvers_set(&client->io, pvers_save);
			return (connect_result);
		}
		switch (axa_apikey_start(emsg, &client->io)) {
		case AXA_IO_OK:
			/* username field holds apikey */
			if (!axa_client_send(emsg, client,
					     AXA_TAG_NONE, AXA_P_OP_USER, &hdr,
					     &client->io.user,
					     sizeof(client->io.user))) {
				axa_client_backoff(client);
				axa_io_pvers_set(&client->io, pvers_save);
				return (AXA_CONNECT_ERR);
			}
			axa_p_to_str(emsg->c, sizeof(emsg->c),
				     true, &hdr,
				     (axa_p_body_t *)&client->io.user);
			axa_io_pvers_set(&client->io, pvers_save);
			return (AXA_CONNECT_USER);
		case AXA_IO_ERR:
			axa_client_backoff_max(client);
			axa_io_pvers_set(&client->io, pvers_save);
			return (AXA_CONNECT_ERR);
		case AXA_IO_BUSY:
			AXA_ASSERT(client->io.nonblock);
			axa_io_pvers_set(&client->io, pvers_save);
			return (connect_result);
		case AXA_IO_TUNERR:
		case AXA_IO_KEEPALIVE:
			AXA_FAIL("impossible axa_apikey_start() result");
		}

	case AXA_IO_TYPE_UNKN:
	default:
		axa_pemsg(emsg, "impossible client type");
		axa_client_backoff_max(client);
		axa_io_pvers_set(&client->io, pvers_save);
		return (AXA_CONNECT_ERR);
	}

	/* Send a NOP if we didn't send the user name. */
	if (!axa_client_send(emsg, client, AXA_TAG_NONE, AXA_P_OP_NOP,
			     &hdr, NULL, 0)) {
		axa_client_backoff(client);
		axa_io_pvers_set(&client->io, pvers_save);
		return (AXA_CONNECT_ERR);
	}
	axa_p_to_str(emsg->c, sizeof(emsg->c), true,
		     &hdr, (axa_p_body_t *)&client->io.user);
	return (AXA_CONNECT_NOP);
}

axa_connect_result_t
axa_client_open(axa_emsg_t *emsg, axa_client_t *client, const char *addr,
		bool is_rad, bool tun_debug, int bufsize, bool nonblock)
{
	struct addrinfo *ai;
	const char *p;
	int i;

	axa_client_close(client);

	client->io.is_rad = is_rad;
	client->io.is_client = true;
	client->io.tun_debug = tun_debug;
	client->io.nonblock = nonblock;
	client->io.bufsize = bufsize;
	gettimeofday(&client->retry, NULL);

	p = strpbrk(addr, AXA_WHITESPACE":");
	if (p == NULL) {
		axa_pemsg(emsg,
			"missing AXA transport delimiter in \"%s\"",
			addr);
		axa_client_backoff_max(client);
		return (AXA_CONNECT_ERR);
	}

	client->io.type = axa_io_type_parse(&addr);
	if (client->io.type == AXA_IO_TYPE_UNKN) {
		axa_pemsg(emsg,
			"invalid AXA transport protocol or alias in \"%s\"",
			addr);
		axa_client_backoff_max(client);
		return (AXA_CONNECT_ERR);
	}

	if (addr[0] == '-' || addr[0] == '\0') {
		axa_pemsg(emsg, "invalid server \"%s\"", addr);
		axa_client_backoff_max(client);
		return (AXA_CONNECT_ERR);
	}

	p = strchr(addr, '@');
	if (p == NULL) {
		i = 0;
	} else {
		i = p - addr;
		/* Collect the user name from protocols that provide it. */
		if (client->io.type != AXA_IO_TYPE_TLS) {
			if (i >= (int)sizeof(client->io.user.name)) {
				axa_pemsg(emsg,
					  "server user name \"%.*s\" too long",
					  i, addr);
				axa_client_backoff_max(client);
				return (AXA_CONNECT_ERR);
			}
			memcpy(client->io.user.name, addr, i);
		}
		++i;
	}
	if (addr[0] == '-' || addr[0] == '\0'
	    || addr[i] == '-' || addr[i] == '\0') {
		axa_pemsg(emsg, "invalid server name \"%s\"", addr);
		axa_client_backoff_max(client);
		return (AXA_CONNECT_ERR);
	}

	switch (client->io.type) {
	case AXA_IO_TYPE_UNIX:
		client->io.addr = axa_strdup(addr+i);
		client->io.label = axa_strdup(client->io.addr);
		client->io.su.sa.sa_family = AF_UNIX;
		strlcpy(client->io.su.sun.sun_path, client->io.addr,
			sizeof(client->io.su.sun.sun_path));
#ifdef HAVE_SA_LEN
		client->io.su.sun.sun_len = SUN_LEN(&client->io.su.sun);
#endif
		break;

	case AXA_IO_TYPE_TCP:
		client->io.addr = axa_strdup(addr+i);
		client->io.label = axa_strdup(client->io.addr);
		if (!axa_get_srvr(emsg, client->io.addr, false, &ai)) {
			axa_client_backoff(client);
			return (AXA_CONNECT_ERR);
		}
		memcpy(&client->io.su.sa, ai->ai_addr, ai->ai_addrlen);
		freeaddrinfo(ai);
		break;

	case AXA_IO_TYPE_SSH:
		client->io.addr = axa_strdup(addr);
		client->io.label = axa_strdup(addr);
		break;

	case AXA_IO_TYPE_TLS:
		if (!axa_tls_parse(emsg, &client->io.cert_file,
				   &client->io.key_file,
				   &client->io.addr,
				   addr))
			return (AXA_CONNECT_ERR);
		client->io.label = axa_strdup(client->io.addr);
		if (!axa_get_srvr(emsg, client->io.addr, false, &ai)) {
			axa_client_backoff(client);
			return (AXA_CONNECT_ERR);
		}
		memcpy(&client->io.su.sa, ai->ai_addr, ai->ai_addrlen);
		freeaddrinfo(ai);
		break;

	case AXA_IO_TYPE_APIKEY:
		if (!axa_apikey_parse(emsg, &client->io.addr,
					&client->io.user, addr))
			return (AXA_CONNECT_ERR);
		client->io.label = axa_strdup(client->io.addr);
		if (!axa_get_srvr(emsg, client->io.addr, false, &ai)) {
			axa_client_backoff(client);
			return (AXA_CONNECT_ERR);
		}
		memcpy(&client->io.su.sa, ai->ai_addr, ai->ai_addrlen);
		freeaddrinfo(ai);
		break;

	case AXA_IO_TYPE_UNKN:
	default:
		AXA_FAIL("impossible client type");
	}

	return (axa_client_connect(emsg, client));
}

bool
axa_client_send(axa_emsg_t *emsg, axa_client_t *client,
		axa_tag_t tag, axa_p_op_t op, axa_p_hdr_t *hdr,
		const void *body, size_t body_len)
{
	axa_io_result_t io_result;

	if (!AXA_CLIENT_CONNECTED(client)) {
		axa_pemsg(emsg, "not connected before output");
		return (false);
	}
	io_result = axa_send(emsg, &client->io, tag, op, hdr,
			     body, body_len, NULL, 0);
	switch (io_result) {
	case AXA_IO_OK:
		break;
	case AXA_IO_BUSY:
		strlcpy(emsg->c, "output busy", sizeof(emsg->c));
		return (false);
	case AXA_IO_ERR:
		return (false);
	case AXA_IO_TUNERR:
	case AXA_IO_KEEPALIVE:
	default:
		AXA_FAIL("impossible axa_send() result");
	}

	return (true);
}

bool
axa_client_get_hello_string(axa_emsg_t *emsg, const char *origin,
		axa_client_t *client, char **out)
{
	int yajl_rc;
	yajl_gen g = NULL;
	struct axa_strbuf *sb = NULL;
	char hostname[HOST_NAME_MAX] = {0};
	struct utsname utsbuf;

	sb = axa_strbuf_init();
	if (sb == NULL) {
		axa_pemsg(emsg, "could not allocate axa_strbuf");
		return (false);
	}

	g = yajl_gen_alloc(NULL);
	AXA_ASSERT (g != NULL);

	yajl_rc = yajl_gen_config(g,
			yajl_gen_print_callback,
			_callback_print_yajl_axa_strbuf,
			sb);
	AXA_ASSERT(yajl_rc != 0);

	add_yajl_map(g);

	if (0 > gethostname(hostname, sizeof(hostname) - 1)) {
		axa_pemsg(emsg, "gethostname(): %s", strerror(errno));
		goto err;
	}
	add_yajl_string(g, "hostname");
	add_yajl_string(g, hostname);

	if (uname(&utsbuf) < 0) {
		axa_pemsg(emsg, "uname(): %s", strerror(errno));
		goto err;
	} else {
		add_yajl_string(g, "uname_sysname");
		add_yajl_string(g, utsbuf.sysname);
		add_yajl_string(g, "uname_release");
		add_yajl_string(g, utsbuf.release);
		add_yajl_string(g, "uname_version");
		add_yajl_string(g, utsbuf.version);
		add_yajl_string(g, "uname_machine");
		add_yajl_string(g, utsbuf.machine);
	}

	add_yajl_string(g, "origin");
	if (origin == NULL) {
		add_yajl_string(g, "unknown");
	}
	else {
		add_yajl_string(g, origin);
	}

	add_yajl_string(g, "libaxa");
	add_yajl_string(g, axa_get_version());

	add_yajl_string(g, "libnmsg");
#ifdef NMSG_LIBRARY_VERSION
	add_yajl_string(g, nmsg_get_version());
#else
	add_yajl_string(g, "<=0.13.2");
#endif
	add_yajl_string(g, "libwdns");
#ifdef WDNS_LIBRARY_VERSION
	add_yajl_string(g, wdns_get_version());
#else
	add_yajl_string(g, "<=0.9.1");
#endif
	add_yajl_string(g, "libyajl");
	add_yajl_integer(g, yajl_version());
	add_yajl_string(g, "OpenSSL");
	add_yajl_string(g, SSLeay_version(SSLEAY_VERSION));
	add_yajl_string(g, "libprotobuf-c");
	add_yajl_string(g, PROTOBUF_C_VERSION);

	add_yajl_string(g, "AXA protocol");
	add_yajl_integer(g, client->io.pvers);

	close_yajl_map(g);

	yajl_gen_reset(g, "");
	yajl_gen_free(g);

	*out = sb->data;
	/* Don't call axa_strbuf_destroy() here, rather, free the wrapper
	 * structure now and leave it to the caller to release sb->data. */
	free(sb);

	return (true);
err:
	if (g != NULL)
		yajl_gen_free(g);
	axa_strbuf_destroy(&sb);
	return (false);
}

/* Process AXA_P_OP_HELLO from the server. */
bool
axa_client_hello(axa_emsg_t *emsg, axa_client_t *client,
		 const axa_p_hello_t *hello, const char *origin)
{
	axa_p_hdr_t hdr;
	axa_p_hello_t *cl_hello;
	size_t len;
	char op_buf[AXA_P_OP_STRLEN], *p, *out = NULL;

	/* Assume by default that the incoming HELLO is the latest message
	 * in the client structure. */
	if (hello == NULL) {
		if (client->io.recv_body == NULL) {
			axa_pemsg(emsg, "no received AXA message ready");
			return (false);
		}
		hello = &client->io.recv_body->hello;
	}

	/* There must be one HELLO per session. */
	if (client->hello != NULL) {
		axa_pemsg(emsg, "duplicate %s",
			  axa_op_to_str(op_buf, sizeof(op_buf),
					AXA_P_OP_HELLO));
		return (false);
	}
	client->hello = axa_strdup(hello->str);

	/* Save bundle ID for AXA_P_OP_JOIN */
	client->clnt_id = hello->id;
	client->have_id = true;

	/* Save the protocol version that the server requires. */
	client->io.pvers = AXA_P_PVERS;
	if (client->io.pvers < hello->pvers_min)
		client->io.pvers = hello->pvers_min;
	if (client->io.pvers > hello->pvers_max)
		client->io.pvers = hello->pvers_max;

	/* Limit the version to one that we can understand.
	 * Just hope for the best if the server did not offer a version
	 * that we can use.  */
	if (client->io.pvers < AXA_P_PVERS_MIN)
		client->io.pvers = AXA_P_PVERS_MIN;
	if (client->io.pvers > AXA_P_PVERS_MAX)
		client->io.pvers = AXA_P_PVERS_MAX;

	/* client -> server HELLO was introduced in AXA_P_VERS2 */
	if (hello->pvers_max < AXA_P_PVERS2)
		return (true);

        cl_hello = AXA_SALLOC(axa_p_hello_t);
        cl_hello->id = hello->id;
        cl_hello->pvers_min = AXA_P_PVERS_MIN;
        cl_hello->pvers_max = AXA_P_PVERS_MAX;

	p = cl_hello->str;
	len = sizeof (cl_hello->str);
	if (!axa_client_get_hello_string(emsg, origin, client, &out)) {
		axa_error_msg("error getting detailed HELLO info: %s",
				emsg->c);
		if (origin == NULL)
			origin = "[unknown]";

		snprintf(cl_hello->str, sizeof (cl_hello->str) - 1,
				"%s %s AXA protocol %d",
				origin, axa_get_version(), AXA_P_PVERS);
	}
	else {
		/* Note, if strlen(out) is > sizeof (*p), the json blob will be
		 * fouled. */
		axa_buf_print(&p, &len, "%s", out);
		free(out);
	}

	axa_client_send(emsg, client, AXA_TAG_NONE, AXA_P_OP_HELLO, &hdr,
			cl_hello, sizeof(*cl_hello) -
			sizeof(cl_hello->str) + strlen(cl_hello->str) + 1);
	free(cl_hello);

	return (true);
}
