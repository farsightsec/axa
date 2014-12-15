/*
 * radd, radtool, and sratool common client code
 *
 *  Copyright (c) 2014-2015 by Farsight Security, Inc.
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

#include <errno.h>
#include <fcntl.h>
#include <stdlib.h>
#include <signal.h>
#include <string.h>
#ifdef __linux
#include <bsd/string.h>			/* for strlcpy() */
#endif
#include <sysexits.h>
#include <sys/wait.h>
#include <unistd.h>


#define	MIN_BACKOFF_MS	(1*1000)
#define	MAX_BACKOFF_MS	(60*1000)

void
axa_client_init(axa_client_t *client)
{
	time_t backoff;
	struct timeval retry;
	bool is_rad;

	/* Do not change the permanent state. */
	backoff = client->backoff;
	retry = client->retry;
	is_rad = client->is_rad;

	memset(client, 0, sizeof(*client));
	client->su.sa.sa_family = -1;
	client->in_sock = -1;
	client->out_sock = -1;
	client->err_sock = -1;
	client->ssh_pid = -1;
	client->pvers = AXA_P_PVERS;

	client->retry = retry;
	client->backoff = backoff;
	client->is_rad = is_rad;

	/* client->alive is 0 to ensure that we immediately send
	 * an AXA_P_OP_NOP (if not an AXA_P_OP_USER) to announce our
	 * protocol version. */
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
axa_client_flush(axa_client_t *client)
{
	if (client->recv_body != NULL) {
		free(client->recv_body);
		client->recv_body = NULL;
	}
	client->recv_len = 0;
}

void
axa_client_close(axa_client_t *client)
{
	int wstatus;

	/* Release buffers. */
	axa_client_flush(client);

	if (client->buf.data != NULL) {
		free(client->buf.data);
		client->buf.data = NULL;
	}

	if (client->addr != NULL) {
		free(client->addr);
		client->addr = NULL;
	}

	if (client->hello != NULL) {
		free(client->hello);
		client->hello = NULL;
	}

	if (client->out_sock >= 0)
		close(client->out_sock);
	if (client->in_sock != client->out_sock)
		close(client->in_sock);
	if (client->err_sock != -1)
		close(client->err_sock);

	/* Kill the ssh tunnel. */
	if (client->ssh_pid != -1) {
		kill(client->ssh_pid, SIGKILL);
		waitpid(client->ssh_pid, &wstatus, 0);
	}

	/* Clear the FDs, PID, and everything else. */
	axa_client_init(client);
}

static bool
connect_ssh(axa_emsg_t *emsg, axa_client_t *client,
	    bool nonblock, bool ssh_debug)
{
	int in_fildes[2], out_fildes[2], err_fildes[2];

	if (0 > pipe(in_fildes)) {
		axa_pemsg(emsg, "pipe(%s): %s", client->addr, strerror(errno));
		return (false);
	}
	if (0 > pipe(out_fildes)) {
		axa_pemsg(emsg, "pipe(%s): %s", client->addr, strerror(errno));
		close(in_fildes[0]);
		close(in_fildes[1]);
		return (false);
	}
	if (0 > pipe(err_fildes)) {
		axa_pemsg(emsg, "pipe(%s): %s", client->addr, strerror(errno));
		close(in_fildes[0]);
		close(in_fildes[1]);
		close(out_fildes[0]);
		close(out_fildes[1]);
		return (false);
	}
	client->ssh_pid = fork();
	if (client->ssh_pid == -1) {
		axa_pemsg(emsg, "ssh fork(%s): %s",
			  client->addr, strerror(errno));
		close(in_fildes[0]);
		close(in_fildes[1]);
		close(out_fildes[0]);
		close(out_fildes[1]);
		close(err_fildes[0]);
		close(err_fildes[1]);
		return (false);
	}
	if (client->ssh_pid == 0) {
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
				      client->addr, strerror(errno));
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
			       client->addr, NULL);
		else
			execlp("ssh", "ssh",
			       "-Tax", "-oBatchMode=yes",
			       "-oStrictHostKeyChecking=no",
			       "-oCheckHostIP=no",
			       "-enone",
			       client->addr, NULL);
		axa_error_msg("exec(ssh): %s", strerror(errno));
		exit(EX_OSERR);
	}

	/* Finish setting up links to ssh child in this the parent. */
	client->in_sock = in_fildes[0];
	client->out_sock = out_fildes[1];
	client->err_sock = err_fildes[0];
	close(in_fildes[1]);
	close(out_fildes[0]);
	close(err_fildes[1]);

	if (!axa_set_sock(emsg, client->in_sock, client->addr,
			  nonblock)
	    || !axa_set_sock(emsg, client->out_sock, client->addr,
			     nonblock)
	    || !axa_set_sock(emsg, client->err_sock, client->addr,
			     true))  {
		return (false);
	}

	return (true);
}

axa_client_connect_result_t
axa_client_connect(axa_emsg_t *emsg, axa_client_t *client, bool nonblock)
{
	axa_p_hdr_t hdr;
	int i;

	if (AXA_CLIENT_CONNECTED(client))
		return (AXA_CLIENT_CONNECT_DONE);

	switch (client->type) {
	case CLIENT_TYPE_UNIX:
	case CLIENT_TYPE_TCP:
		if (!AXA_CLIENT_OPENED(client)) {
			client->out_sock = socket(client->su.sa.sa_family,
						  SOCK_STREAM, 0);
			client->in_sock = client->out_sock;
			if (client->out_sock < 0) {
				axa_pemsg(emsg, "socket(%s): %s",
					  client->addr, strerror(errno));
				axa_client_backoff_max(client);
				return (AXA_CLIENT_CONNECT_BAD);
			}
			if (!axa_set_sock(emsg, client->out_sock, client->addr,
					  nonblock))  {
				axa_client_backoff_max(client);
				return (AXA_CLIENT_CONNECT_BAD);
			}
		}

		if (!AXA_CLIENT_CONNECTED(client)) {
			i = connect(client->out_sock,
				    &client->su.sa, AXA_SU_LEN(&client->su));
			if (0 <= i || errno == EISCONN) {
				/* We finished a new connection or a previously
				 * started non-blocking connection. */
				client->connected = true;

			} else if (nonblock && AXA_CONN_WAIT_ERRORS()) {
				/* Non-blocking connection unfinished. */
				return (AXA_CLIENT_CONNECT_INCOM);

			} else {
				/* Failed to connect. */
				axa_pemsg(emsg, "connect(%s): %s",
					  client->addr, strerror(errno));
				axa_client_backoff(client);
				return (AXA_CLIENT_CONNECT_TEMP);
			}
		}

		/* TCP and UNIX domain sockets need a user name */
		if (client->user.name[0] != '\0') {
			if (!axa_client_send(emsg, client,
					     AXA_TAG_NONE, AXA_P_OP_USER, &hdr,
					     &client->user,
					     sizeof(client->user))) {
				axa_client_backoff(client);
				return (AXA_CLIENT_CONNECT_BAD);
			}
			axa_p_to_str(emsg->c, sizeof(emsg->c),
				     true, &hdr,
				     (axa_p_body_t *)&client->user);
			return (AXA_CLIENT_CONNECT_USER);
		}
		break;

	case CLIENT_TYPE_SSH:
		if (!AXA_CLIENT_OPENED(client)) {
			if (!connect_ssh(emsg, client, nonblock,
					 client->debug_on)) {
				axa_client_backoff_max(client);
				return (AXA_CLIENT_CONNECT_BAD);
			}
			client->connected = true;
		}
		break;

	case CLIENT_TYPE_UNKN:
	default:
		axa_pemsg(emsg, "impossible client type");
		axa_client_backoff_max(client);
		return (AXA_CLIENT_CONNECT_BAD);
	}

	if (!axa_client_send(emsg, client, AXA_TAG_NONE, AXA_P_OP_NOP,
			     &hdr, NULL, 0)) {
		axa_client_backoff(client);
		return (AXA_CLIENT_CONNECT_BAD);
	}
	axa_p_to_str(emsg->c, sizeof(emsg->c), true,
		     &hdr, (axa_p_body_t *)&client->user);
	return (AXA_CLIENT_CONNECT_NOP);
}

axa_client_connect_result_t
axa_client_open(axa_emsg_t *emsg, axa_client_t *client,
		const char *addr, bool is_rad, bool debug_on, bool nonblock)
{
	struct addrinfo *ai;
	const char *p;
	int i;

	axa_client_close(client);

	client->is_rad = is_rad;
	client->debug_on = debug_on;
	gettimeofday(&client->retry, NULL);

	p = strpbrk(addr, AXA_WHITESPACE":");
	if (p == NULL) {
		axa_pemsg(emsg, "invalid AXA transport protocol \"%s\"", addr);
		axa_client_backoff_max(client);
		return (AXA_CLIENT_CONNECT_BAD);
	}

	if (AXA_CLITCMP(addr, CLIENT_TYPE_UNIX_STR":")) {
		client->type = CLIENT_TYPE_UNIX;
	} else if (AXA_CLITCMP(addr, CLIENT_TYPE_TCP_STR":")) {
		client->type = CLIENT_TYPE_TCP;
	} else if (AXA_CLITCMP(addr, CLIENT_TYPE_SSH_STR":")
		   || AXA_CLITCMP(addr, CLIENT_TYPE_SSH_STR" ")) {
		/* allow "ssh " for upward compatibility for old sratool */
		client->type = CLIENT_TYPE_SSH;
	} else {
		axa_pemsg(emsg, "invalid AXA transport protocol \"%s\"", addr);
		axa_client_backoff_max(client);
		return (AXA_CLIENT_CONNECT_BAD);
	}
	addr = p + strspn(p, AXA_WHITESPACE":");

	if (addr[0] == '-' || addr[0] == '\0') {
		axa_pemsg(emsg, "invalid server \"%s\"", addr);
		axa_client_backoff_max(client);
		return (AXA_CLIENT_CONNECT_BAD);
	}

	p = strchr(addr, '@');
	if (p == NULL) {
		i = 0;
	} else {
		i = p - addr;
		if (i >= (int)sizeof(client->user.name)) {
			axa_pemsg(emsg, "server user name \"%.*s\" too long",
				  i, addr);
			axa_client_backoff_max(client);
			return (AXA_CLIENT_CONNECT_BAD);
		}
		memcpy(client->user.name, addr, i);
		++i;
	}
	if (addr[0] == '-' || addr[0] == '\0'
	    || addr[i] == '-' || addr[i] == '\0') {
		axa_pemsg(emsg, "invalid server name \"%s\"", addr);
		axa_client_backoff_max(client);
		return (AXA_CLIENT_CONNECT_BAD);
	}

	switch (client->type) {
	case CLIENT_TYPE_UNIX:
		client->addr = strdup(addr+i);
		client->su.sa.sa_family = AF_UNIX;
		strlcpy(client->su.sun.sun_path, client->addr,
			sizeof(client->su.sun.sun_path));
#ifdef HAVE_SA_LEN
		client->su.sun.sun_len = SUN_LEN(&client->su.sun);
#endif
		break;

	case CLIENT_TYPE_TCP:
		client->addr = strdup(addr+i);
		if (!axa_get_srvr(emsg, client->addr, false, &ai)) {
			axa_client_backoff(client);
			return (AXA_CLIENT_CONNECT_BAD);
		}
		memcpy(&client->su.sa, ai->ai_addr, ai->ai_addrlen);
		freeaddrinfo(ai);
		break;

	case CLIENT_TYPE_SSH:
		client->addr = strdup(addr);
		break;

	case CLIENT_TYPE_UNKN:
	default:
		AXA_FAIL("impossible client type");
	}

	return (axa_client_connect(emsg, client, nonblock));
}

bool
axa_client_send(axa_emsg_t *emsg, axa_client_t *client,
		axa_tag_t tag, axa_p_op_t op, axa_p_hdr_t *hdr,
		const void *body, size_t body_len)
{
	if (!AXA_CLIENT_CONNECTED(client)) {
		axa_pemsg(emsg, "not connected before output");
		return (false);
	}
	switch (axa_p_send(emsg, client->out_sock, client->pvers, tag, op, hdr,
			   body, body_len, NULL, 0, NULL, client->addr,
			   client->is_rad ? AXA_P_TO_RAD : AXA_P_TO_SRA,
			   &client->alive)) {
	case AXA_P_SEND_OK:
		return (true);
	case AXA_P_SEND_BUSY:
		strlcpy(emsg->c, "output busy", sizeof(emsg->c));
		return (false);
	case AXA_P_SEND_BAD:
		return (false);
	}
	AXA_FAIL("impossible axa_p_send() result");
}

/* Wait for something to to happen on the inputs. */
axa_client_recv_result_t
axa_client_recv_wait(axa_emsg_t *emsg, axa_client_t *client, time_t wait_ms)
{
	struct timeval now;
	time_t ms;
	struct pollfd pollfds[2];
	int nfds, in_poll_nfd, err_poll_nfd;
	int i;

	if (wait_ms < 0)
		wait_ms = 0;

	/* Stop waiting when it is time for a keepalive. */
	if (AXA_CLIENT_CONNECTED(client)) {
		gettimeofday(&now, NULL);
		ms = (AXA_KEEPALIVE_MS - axa_elapsed_ms(&now, &client->alive));
		if (wait_ms > ms)
			wait_ms = ms;
	}

	memset(pollfds, 0, sizeof(pollfds));
	in_poll_nfd = -1;
	err_poll_nfd = -1;
	nfds = 0;

	if (client->in_sock >= 0) {
		pollfds[nfds].fd = client->in_sock;
		pollfds[nfds].events = AXA_POLL_IN;
		in_poll_nfd = nfds++;
	}

	/* Watch stderr pipe from ssh. */
	if (client->err_sock >= 0) {
		pollfds[nfds].fd = client->err_sock;
		pollfds[nfds].events = AXA_POLL_IN;
		err_poll_nfd = nfds++;
	}

	i = poll(pollfds, nfds, wait_ms);
	if (i == 0)
		return (AXA_CLIENT_RECV_INCOM);
	if (i < 0) {
		if (errno == EINTR || errno == EAGAIN)
			return (AXA_CLIENT_RECV_INCOM);
		axa_pemsg(emsg, "poll(): %s", strerror(errno));
		return (AXA_CLIENT_RECV_ERR);
	}

	if (err_poll_nfd >= 0
	    && pollfds[err_poll_nfd].revents != 0)
		return (AXA_CLIENT_RECV_STDERR);

	if (pollfds[in_poll_nfd].revents != 0)
		return (AXA_CLIENT_RECV_DONE);

	if (AXA_CLIENT_CONNECTED(client)) {
		gettimeofday(&now, NULL);
		ms = (AXA_KEEPALIVE_MS - axa_elapsed_ms(&now, &client->alive));
		if (ms <= 0)
			return (AXA_CLIENT_RECV_KEEPALIVE);
	}
	return (AXA_CLIENT_RECV_INCOM);
}

/*  Wait for and read an AXA message from the server into the client buffer. */
axa_client_recv_result_t
axa_client_recv(axa_emsg_t *emsg, axa_client_t *client, time_t wait_ms)
{
	axa_client_recv_result_t result;
	axa_p_recv_result_t p_recv_result;

	for (;;) {
		if (!AXA_CLIENT_OPENED(client)) {
			axa_pemsg(emsg, "not open");
			return (AXA_CLIENT_RECV_ERR);
		}
		if (!AXA_CLIENT_CONNECTED(client)) {
			axa_pemsg(emsg, "not connected");
			return (AXA_CLIENT_RECV_ERR);
		}

		if (client->buf.data == NULL || client->buf.data_len == 0) {
			result = axa_client_recv_wait(emsg, client, wait_ms);
			switch (result) {
			case AXA_CLIENT_RECV_ERR:
			case AXA_CLIENT_RECV_STDERR:
			case AXA_CLIENT_RECV_KEEPALIVE:
			case AXA_CLIENT_RECV_INCOM:
				return (result);

			case AXA_CLIENT_RECV_DONE:
				break;
			}
		}

		p_recv_result = axa_p_recv(emsg, client->in_sock,
					   &client->recv_hdr,
					   &client->recv_body, &client->recv_len,
					   &client->buf, client->addr,
					   client->is_rad ? AXA_P_FROM_RAD
					   : AXA_P_FROM_SRA,
					   &client->alive);
		switch (p_recv_result) {
		case AXA_P_RECV_ERR:
			return (AXA_CLIENT_RECV_ERR);
		case AXA_P_RECV_INCOM:
			continue;
		case AXA_P_RECV_DONE:
			return (AXA_CLIENT_RECV_DONE);
		default:
			AXA_FAIL("impossible axa_p_recv() result");
		}
	}
}

/* Process AXA_P_OP_HELLO from the server. */
bool
axa_client_hello(axa_emsg_t *emsg, axa_client_t *client,
		 const axa_p_hello_t *hello)
{
	char op_buf[AXA_P_OP_STRLEN];

	/* Assume by default that the incoming HELLO is the latest message
	 * in the client structure. */
	if (hello == NULL) {
		if (client->recv_body == NULL) {
			axa_pemsg(emsg, "no received AXA message ready");
			return (false);
		}
		hello = &client->recv_body->hello;
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
	client->pvers = AXA_P_PVERS;
	if (client->pvers < hello->pvers_min)
		client->pvers = hello->pvers_min;
	if (client->pvers > hello->pvers_max)
		client->pvers = hello->pvers_max;

	/* Limit the version to one that we can understand.
	 * Just hope for the best if the server did not offer a version
	 * that we can use.  */
	if (client->pvers < AXA_P_PVERS_MIN)
		client->pvers = AXA_P_PVERS_MIN;
	if (client->pvers > AXA_P_PVERS_MAX)
		client->pvers = AXA_P_PVERS_MAX;

	return (true);
}

/* Capture anything that the ssh process says. */
const char *				/* NULL or \'0' terminated string */
axa_client_stderr(axa_client_t *client)
{
	int i;
	char *p;

	for (;;) {
		/* Discard the previously returned line. */
		if (client->ebuf_bol != 0) {
			i = client->ebuf_len - client->ebuf_bol;
			if (i > 0)
				memmove(client->ebuf,
					&client->ebuf[client->ebuf_bol],
					i);
			client->ebuf_len -= client->ebuf_bol;
			client->ebuf_bol = 0;
		}

		/* Hope to return the next line in the buffer. */
		if (client->ebuf_len > 0) {
			i = min(client->ebuf_len, 120);
			p = memchr(client->ebuf, '\n', i);
			if (p != NULL) {
				*p = '\0';
				client->ebuf_bol = p+1 - client->ebuf;

				/* trim '\r' */
				while (p > client->ebuf
				       && *--p == '\r')
					*p = '\0';
				/* Discard blank lines. */
				if (p == client->ebuf)
					continue;
				return (client->ebuf);
			}
		}

		/* Get more data, possibly completing a partial line,
		 * if there is room in the buffer.
		 * If not, return whatever we have. */
		i = sizeof(client->ebuf)-1 - client->ebuf_len;
		if (i > 0 && client->err_sock >= 0) {
			i = read(client->err_sock,
				 &client->ebuf[client->ebuf_len],
				 i);

			/* Return the 1st line in the new buffer load */
			if (i > 0) {
				client->ebuf_len += i;
				client->ebuf[client->ebuf_len] = '\0';
				continue;
			}

			/* Return an error message at error. */
			if (i < 0 && errno != EWOULDBLOCK && errno != EAGAIN
			    && errno != EINTR) {
				snprintf(client->ebuf, sizeof(client->ebuf),
					 "read(ssh stderr): %s",
					 strerror(errno));
				client->ebuf_len = strlen(client->ebuf)+1;
				close(client->err_sock);
				client->err_sock = -1;

			} else if (i == 0) {
				close(client->err_sock);
				client->err_sock = -1;
			}
		}

		/* Return whatever we have. */
		client->ebuf_bol = client->ebuf_len;
		return ((client->ebuf_len > 0) ? client->ebuf : NULL);
	}
}
