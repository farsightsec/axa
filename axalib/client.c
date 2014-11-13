/*
 * radd, radtool, and sratool common client code
 *
 *  Copyright (c) 2014 by Farsight Security, Inc.
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

	/* Do not change the back-off state. */
	backoff = client->backoff;
	retry = client->retry;

	memset(client, 0, sizeof(*client));
	client->su.sa.sa_family = -1;
	client->in_sock = -1;
	client->out_sock = -1;
	client->err_sock = -1;
	client->ssh_pid = -1;
	client->pvers = AXA_P_PVERS;

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


time_t
axa_client_again(axa_client_t *client, struct timeval *now)
{
	time_t ms;

	if (client->retry.tv_sec == 0)
		return (-1);

	gettimeofday(now, NULL);
	ms = client->backoff - axa_tv_diff2ms(now, &client->retry);
	if (ms <= 0 || ms > client->backoff) /* deal with time jump */
		return (-1);
	return (ms);
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

int
axa_client_connect(axa_emsg_t *emsg, axa_client_t *client, bool nonblock)
{
	int i;

	if (client->nonblock_connect) {
		/* Require consistency with a previously started
		 * a non-blocking connection attempt. */
		AXA_ASSERT(nonblock);
		AXA_ASSERT(client->out_sock >= 0);

	} else {
		/* Start to connect. */
		AXA_ASSERT(client->out_sock < 0);

		client->out_sock = socket(client->su.sa.sa_family,
					  SOCK_STREAM, 0);
		client->in_sock = client->out_sock;
		if (client->out_sock < 0) {
			axa_pemsg(emsg, "socket(%s): %s",
				  client->addr, strerror(errno));
			axa_client_backoff(client);
			return (-1);
		}

		if (!axa_set_sock(emsg, client->out_sock, client->addr,
				  nonblock))  {
			axa_client_backoff(client);
			return (-1);
		}
	}

	i = connect(client->out_sock, &client->su.sa, AXA_SU_LEN(&client->su));
	if (0 <= i || (nonblock && errno == EISCONN)) {
		/* New blocking connection
		 * or previously started blocking connection finished. */
		client->nonblock_connect = false;
		return (1);
	}

	if (nonblock && AXA_CONN_WAIT_ERRORS()) {
		/* Non-blocking connection unfinished. */
		client->nonblock_connect = true;
		return (1);
	}

	/* Failed to connect. */
	axa_pemsg(emsg, "%sconnect(%s): %s",
		  client->nonblock_connect ? "later " : "",
		  client->addr, strerror(errno));
	axa_client_backoff(client);
	return (0);
}

static int				/* -1=failed  0=retry  1=success */
connect_ssh(axa_emsg_t *emsg, axa_client_t *client,
	    const char *userhost, bool nonblock, bool debug)
{
	int in_fildes[2], out_fildes[2], err_fildes[2];

	if (0 > pipe(in_fildes)) {
		axa_pemsg(emsg, "pipe(%s): %s", client->addr, strerror(errno));
		axa_client_backoff(client);
		return (-1);
	}
	if (0 > pipe(out_fildes)) {
		axa_pemsg(emsg, "pipe(%s): %s", client->addr, strerror(errno));
		close(in_fildes[0]);
		close(in_fildes[1]);
		axa_client_backoff(client);
		return (-1);
	}
	if (0 > pipe(err_fildes)) {
		axa_pemsg(emsg, "pipe(%s): %s", client->addr, strerror(errno));
		close(in_fildes[0]);
		close(in_fildes[1]);
		close(out_fildes[0]);
		close(out_fildes[1]);
		axa_client_backoff(client);
		return (-1);
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
		axa_client_backoff(client);
		return (-1);
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

		if (debug)
			execlp("ssh", "ssh", "-v",
			       "-Tax", "-oBatchMode=yes",
			       "-oStrictHostKeyChecking=no",
			       "-oCheckHostIP=no",
			       "-enone",
			       userhost, NULL);
		else
			execlp("ssh", "ssh",
			       "-Tax", "-oBatchMode=yes",
			       "-oStrictHostKeyChecking=no",
			       "-oCheckHostIP=no",
			       "-enone",
			       userhost, NULL);
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
			     nonblock))  {
		axa_client_backoff(client);
		return (-1);
	}

	return (1);
}

int
axa_client_open(axa_emsg_t *emsg, axa_client_t *client,
		const char *addr, bool debug, bool nonblock)
{
	struct addrinfo *ai;
	const char *p;
	int i;

	axa_client_close(client);
	gettimeofday(&client->retry, NULL);

	p = strpbrk(addr, AXA_WHITESPACE":");
	if (p == NULL) {
		axa_pemsg(emsg, "invalid AXA transport protocol \"%s\"", addr);
		axa_client_backoff(client);
		return (-1);
	}

	if (AXA_CLITCMP(addr, CLIENT_TYPE_UNIX_STR":")) {
		client->type = CLIENT_TYPE_UNIX;
	} else if (AXA_CLITCMP(addr, CLIENT_TYPE_TCP_STR":")) {
		client->type = CLIENT_TYPE_TCP;
	} else if (AXA_CLITCMP(addr, CLIENT_TYPE_SSH_STR":")
		   || AXA_CLITCMP(addr, CLIENT_TYPE_SSH_STR" ")) {
		/* allow "ssh ..." for upward compatibility for old sratool */
		client->type = CLIENT_TYPE_SSH;
	} else {
		axa_pemsg(emsg, "invalid AXA transport protocol \"%s\"", addr);
		axa_client_backoff(client);
		return (-1);
	}
	addr = p + strspn(p, AXA_WHITESPACE":");

	if (addr[0] == '-' || addr[0] == '\0') {
		axa_pemsg(emsg, "invalid server \"%s\"", addr);
		axa_client_backoff(client);
		return (-1);
	}

	p = strchr(addr, '@');
	if (p == NULL) {
		i = 0;
	} else {
		i = p - addr;
		if (i >= (int)sizeof(client->user.name)) {
			axa_pemsg(emsg, "server user name \"%.*s\" too long",
				  i, addr);
			axa_client_backoff(client);
			return (-1);
		}
		memcpy(client->user.name, addr, i);
		++i;
	}
	if (addr[0] == '-' || addr[0] == '\0'
	    || addr[i] == '-' || addr[i] == '\0') {
		axa_pemsg(emsg, "invalid server name \"%s\"", addr);
		axa_client_backoff(client);
		return (-1);
	}

	client->addr = strdup(addr+i);

	switch (client->type) {
	case CLIENT_TYPE_UNIX:
		client->su.sa.sa_family = AF_UNIX;
		strlcpy(client->su.sun.sun_path, client->addr,
			sizeof(client->su.sun.sun_path));
#ifdef HAVE_SA_LEN
		client->su.sun.sun_len = SUN_LEN(&client->su.sun);
#endif
		return (axa_client_connect(emsg, client, nonblock));

	case CLIENT_TYPE_TCP:
		if (!axa_get_srvr(emsg, client->addr, false, &ai)) {
			axa_client_backoff(client);
			return (-1);
		}
		memcpy(&client->su.sa, ai->ai_addr, ai->ai_addrlen);
		freeaddrinfo(ai);
		client->addr = axa_strdup(addr);
		return (axa_client_connect(emsg, client, nonblock));

	case CLIENT_TYPE_SSH:
		return (connect_ssh(emsg, client, addr, nonblock, debug));

	case CLIENT_TYPE_UNKN:
	default:
		break;
	}
	AXA_FAIL("impossible client type");
}

void
axa_client_hello(axa_client_t *client, const axa_p_hello_t *hello)
{
	if (client->hello != NULL)
		free(client->hello);
	client->hello = axa_strdup(hello->str);

	/* Save bundle ID for AXA_P_OP_JOIN */
	client->clnt_id = hello->id;
	client->have_id = true;

	client->pvers = AXA_P_PVERS;
	if (client->pvers < hello->pvers_min)
		client->pvers = hello->pvers_min;
	if (client->pvers > hello->pvers_max)
		client->pvers = hello->pvers_max;

	if (client->pvers < AXA_P_PVERS_MIN)
		client->pvers = AXA_P_PVERS_MIN;
	if (client->pvers > AXA_P_PVERS_MAX)
		client->pvers = AXA_P_PVERS_MAX;
}
