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
#include <sys/stat.h>
#include <sys/time.h>
#include <unistd.h>


#define	MIN_BACKOFF    1
#define	MAX_BACKOFF    60

void
axa_client_init(client_t *client)
{
	time_t backoff;

	backoff = client->backoff;
	memset(client, 0, sizeof(*client));
	client->in_sock = -1;
	client->out_sock = -1;
	client->err_sock = -1;
	client->ssh_pid = -1;
	client->pvers = AXA_P_PVERS;
	client->backoff = backoff;
}

void
axa_client_backoff(client_t *client)
{
	axa_client_close(client);

	gettimeofday(&client->retry, NULL);
	client->retry.tv_sec += client->backoff;

	client->backoff = max(MIN_BACKOFF, client->backoff*2);
	if (client->backoff > MAX_BACKOFF)
		client->backoff = MAX_BACKOFF;
}

/* Is it time to try connecting again? */
time_t					/* <0 if yes */
axa_client_again(client_t *client, struct timeval *now)
{
	time_t ms;

	gettimeofday(now, NULL);
	if (client->retry.tv_sec == 0)
		return (-1);
	ms = MAX_BACKOFF - axa_tv_diff2ms(now, &client->retry);
	if (ms <= 0 || ms > MAX_BACKOFF)   /* deal with time jump */
		return (-1);
	return (ms);
}

void
axa_client_flush(client_t *client)
{
	if (client->recv_body != NULL) {
		free(client->recv_body);
		client->recv_body = NULL;
	}
	client->recv_len = 0;
}

void
axa_client_close(client_t *client)
{
	int wstatus;
	int i;

	axa_client_flush(client);

	if (client->addr != NULL) {
		free(client->addr);
		client->addr = NULL;
	}
	for (i = 0; i < AXA_DIM(client->ssh_argv); ++i) {
		if (client->ssh_argv[i] != NULL) {
			free(client->ssh_argv[i]);
			client->ssh_argv[i] = NULL;
		}
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

/* Connect, start connecting non-blocking,
 * or try to finish non-blocking connect. */
bool					/* true=at least started */
axa_client_connect(axa_emsg_t *emsg, client_t *client, bool nonblock)
{
	int i;

	AXA_ASSERT(!client->is_ssh);

	if (client->nonblock_connect) {
		/* Require consistency with a previously started
		 * a non-blocking connection attempt. */
		AXA_ASSERT(nonblock);
		AXA_ASSERT(client->out_sock >= 0);

	} else {
		/* Start a connect. */
		AXA_ASSERT(client->out_sock < 0);

		client->out_sock = socket(client->su.sa.sa_family,
					  SOCK_STREAM, 0);
		client->in_sock = client->out_sock;
		if (client->out_sock < 0) {
			axa_pemsg(emsg, "socket(%s): %s",
				  client->addr, strerror(errno));
			axa_client_backoff(client);
			return (false);
		}

		if (!axa_set_sock(emsg, client->out_sock, client->addr,
				  nonblock))  {
			axa_client_backoff(client);
			return (false);
		}
	}

	i = connect(client->out_sock, &client->su.sa, AXA_SU_LEN(&client->su));
	if (0 <= i || (nonblock && errno == EISCONN)) {
		/* New blocking connection
		 * or previously started blocking connection finished. */
		client->nonblock_connect = false;
		return (true);
	}

	if (nonblock && AXA_CONN_WAIT_ERRORS()) {
		/* Non-blocking connection unfinished. */
		client->nonblock_connect = true;
		return (true);
	}

	/* Failed to connect. */
	axa_pemsg(emsg, "%sconnect(%s): %s",
		  client->nonblock_connect ? "later " : "",
		  client->addr, strerror(errno));
	axa_client_backoff(client);
	return (false);
}

/* Parse a ssh server string */
static bool
ssh_parse(axa_emsg_t *emsg, client_t *client, const char *addr, uint debug)
{
	int argc, num_args;
	/* server name possibly with "ssh user@" */
	char arg[AXA_MAX_SRVRLEN];
	const char *next;

	argc = 0;
	client->ssh_argv[argc++] = axa_strdup("ssh");

	/* No psuedo-ttyp, no X11 forarding,
	 * and no athentication agent connection. */
	client->ssh_argv[argc++] = axa_strdup("-Tax");

	/* Turn on ssh verbosity when debugging the connection. */
	if (debug > AXA_DEBUG_TRACE)
		client->ssh_argv[argc++] = axa_strdup("-v");

	client->ssh_argv[argc++] = axa_strdup("-oBatchMode yes");

	/* Allow args before and after the server name like the ssh command. */
	num_args = 0;
	next = addr;
	while (*next != '\0') {
		/* Reserve space for the terminal NULL. */
		if (argc >= AXA_DIM(client->ssh_argv)-1) {
			axa_pemsg(emsg, "too many ssh args in \"%s...\"",
				  addr);
			return (false);
		}

		if (0 > axa_get_token(arg, sizeof(arg),
				      &next, AXA_WHITESPACE"\\';'\"")) {
			axa_pemsg(emsg, "ssh arg \"%s...\" too long", arg);
			return (false);
		}
		if (strchr("\\';'\"", *(next-1)) != NULL) {
			axa_pemsg(emsg,
				  "illegal character \"%c\" in \"ssh %s\"",
				  *(next-1), addr);
			return (false);
		}

		if (arg[0] == '-') {
			++num_args;
		} else {
			if (client->addr != NULL) {
				axa_pemsg(emsg, "two ssh hosts in \"%s\"",
					  addr);
				return (false);
			}
			client->addr = axa_strdup(arg);
		}
		client->ssh_argv[argc] = axa_strdup(arg);
		++argc;
	}

	if (client->addr == NULL) {
		axa_pemsg(emsg, "missing ssh server name in \"%s\"", addr);
		return (false);
	}

	/* Assume these if there are no ssh args. */
	if (num_args == 0) {
		client->ssh_argv[argc++] = axa_strdup("-oStrictHostKeyChecking=no");
		client->ssh_argv[argc++] = axa_strdup("-oCheckHostIP=no");
	}

	return (true);
}

/*
 * Connect to an SRA or RAD server using TCP/IP, a UNIX domain socket,
 * or an ssh pipe.
 */
bool
axa_client_open(axa_emsg_t *emsg, client_t *client, const char *addr,
		uint debug, bool nonblock)
{
	struct stat sb;
	struct addrinfo *ai;
	size_t wlen;

	axa_client_close(client);

	memset(&client->su, 0, sizeof(client->su));

	/* it is a UNIX domain socket if it is in the file system */
	if (*addr == '/' || 0 <= stat(addr, &sb)) {
		client->addr = axa_strdup(addr);

		client->su.sa.sa_family = AF_UNIX;
		strlcpy(client->su.sun.sun_path, client->addr,
			sizeof(client->su.sun.sun_path));
#ifdef HAVE_SA_LEN
		client->su.sun.sun_len = SUN_LEN(&client->su.sun);
#endif
		return (axa_client_connect(emsg, client, nonblock));

	} else if (AXA_CLITCMP(addr, "ssh")
		   && (wlen = strspn(addr+3, AXA_WHITESPACE)) != 0) {
		/* It is "ssh server" if it starts with "ssh ". */
		int in_fildes[2], out_fildes[2], err_fildes[2];

		if (!ssh_parse(emsg, client, addr+3+wlen, debug))
			return (false);

		client->su.sa.sa_family = -1;
		if (0 > pipe(in_fildes)) {
			axa_pemsg(emsg, "pipe(%s): %s",
				  client->addr, strerror(errno));
			axa_client_backoff(client);
			return (false);
		}
		if (0 > pipe(out_fildes)) {
			axa_pemsg(emsg, "pipe(%s): %s",
				  client->addr, strerror(errno));
			close(in_fildes[0]);
			close(in_fildes[1]);
			axa_client_backoff(client);
			return (false);
		}
		if (0 > pipe(err_fildes)) {
			axa_pemsg(emsg, "pipe(%s): %s",
				  client->addr, strerror(errno));
			close(in_fildes[0]);
			close(in_fildes[1]);
			close(out_fildes[0]);
			close(out_fildes[1]);
			axa_client_backoff(client);
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
			axa_client_backoff(client);
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
				axa_error_msg("ssh dup2(): %s", strerror(errno));
				exit(EX_OSERR);
			}
			close(in_fildes[0]);
			close(out_fildes[1]);
			close(err_fildes[0]);

			execvp("ssh", client->ssh_argv);
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
				  false)
		    || !axa_set_sock(emsg, client->out_sock, client->addr,
				     false)) {
			axa_client_backoff(client);
			return (false);
		}
		/* Set STDERR from ssh non-blocking. */
		if (!axa_set_sock(emsg, client->err_sock, client->addr,
				  true))  {
			axa_client_backoff(client);
			return (false);
		}

	} else {
		/* otherwise try to connect via TCP/IP to "hostname,port" */
		if (!axa_get_srvr(emsg, addr, false, &ai)) {
			axa_client_backoff(client);
			return (false);
		}
		memcpy(&client->su.sa, ai->ai_addr, ai->ai_addrlen);
		freeaddrinfo(ai);
		client->addr = axa_strdup(addr);

		return (axa_client_connect(emsg, client, nonblock));
	}

	return (true);
}

/*
 * Examine AXA protocol HELLO from server to pick a common protocol version.
 */
void
axa_client_hello(client_t *client, const axa_p_hello_t* hello)
{
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

	client->pvers_known = true;
}
