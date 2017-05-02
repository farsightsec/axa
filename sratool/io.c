/*
 * SIE Remote Access (SRA) ASCII tool
 *
 *  Copyright (c) 2014-2017 by Farsight Security, Inc.
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

#include "sratool.h"

/* extern: cmd.c */
extern EditLine *el_e;
extern struct timeval cmd_input;
extern struct timeval prompt_cleared;
extern struct timeval no_reprompt;
extern struct timeval last_output;

/* extern: infile.c */
extern int in_file_cur;

/* extern: main.c */
extern bool interrupted;

/* extern: server.c */
extern axa_client_t client;

void
io_wait(bool cmds_ok,			/* false=waiting for connect */
	bool once,
	time_t wait_ms)
{
	struct timeval now;
	struct timeval start;
	int poll_ms, ms;		/* poll() wants an int */
	struct pollfd pollfds[4];
	bool data_ok;
	const char *cp;
	int cmd_nfd, i_nfd, o_nfd, tun_nfd, nfds, i;

	gettimeofday(&start, NULL);
	do {
		nfds = 0;
		cmd_nfd = -1;
		i_nfd = -1;
		o_nfd = -1;
		tun_nfd = -1;

		gettimeofday(&now, NULL);
		poll_ms = wait_ms - axa_elapsed_ms(&now, &start);
		if (poll_ms <= 0)
			return;
		data_ok = true;

		if (cmds_ok) {
			if (in_file_cur >= 0) {
				AXA_ASSERT(in_file_cur == 0);
				/* We will poll the primary input. */
				pollfds[nfds].fd = STDIN_FILENO;
				pollfds[nfds].events = AXA_POLL_IN;
			} else {
				/* After EOF from the primary input,
				 * wait until the server connection breaks
				 * or until we cannot output. */
				if (!AXA_CLIENT_OPENED(&client))
					stop(EX_OK);
				pollfds[nfds].fd = STDOUT_FILENO;
				pollfds[nfds].events = 0;
			}
			pollfds[nfds].revents = 0;
			cmd_nfd = nfds++;

			/* Give the user 5 seconds without interruption
			 * to finish typing. */
			if (cmd_input.tv_sec != 0
			    && 0 < (ms = 5*1000- axa_elapsed_ms(&now,
							&cmd_input))) {
				data_ok = false;
				if (poll_ms > ms)
					poll_ms = ms;
			}

			/* Delay restoring the prompt until
			 * the server has been quiet 0.5 seconds. */
			if (prompt_cleared.tv_sec != 0) {
				ms = 100 - axa_elapsed_ms(&now, &no_reprompt);
				if (ms <= 0) {
					ms = 500 - axa_elapsed_ms(&now,
							&prompt_cleared);
					if (ms <= 0
					    || !AXA_CLIENT_OPENED(&client)) {
					    reprompt();
					    continue;
					}
				}
				if (poll_ms > 1000)
					poll_ms = 1000;
			}
		}

		/* If the connection is complete,
		 * if we are not about to send the user name,
		 * if we have not heard from the server,
		 * and if the user is not typing,
		 * then send a NOP to test the connection. */
		if (data_ok
		    && AXA_CLIENT_CONNECTED(&client)) {
			ms = (AXA_KEEPALIVE_MS
			      - axa_elapsed_ms(&now, &client.io.alive));
			if (ms <= 0) {
				srvr_send(AXA_TAG_NONE, AXA_P_OP_NOP, NULL, 0);
				continue;
			}
			if (poll_ms > ms)
				poll_ms = ms;
		}

		if (AXA_CLIENT_OPENED(&client)) {
			if (data_ok) {
				if (client.io.i_fd >= 0
				    && client.io.i_events != 0) {
					pollfds[nfds].fd = client.io.i_fd;
					pollfds[nfds].events=client.io.i_events;
					i_nfd = nfds++;
				}

				if (client.io.o_fd >= 0
				    && client.io.o_events != 0) {
					pollfds[nfds].fd = client.io.o_fd;
					pollfds[nfds].events=client.io.o_events;
					o_nfd = nfds++;
				}

				/* Watch stderr from ssh. */
				if (client.io.tun_fd >= 0) {
					pollfds[nfds].fd = client.io.tun_fd;
					pollfds[nfds].events = AXA_POLL_IN;
					tun_nfd = nfds++;
				}
			}

			/* Flush the forwarding buffer
			 * when the SRA server goes quiet. */
			poll_ms = out_flush_ck(&now, poll_ms);
		}

		/* Flush piped stdio output when quiet. */
		if (el_e == NULL && last_output.tv_sec != 0) {
			ms = 200 - axa_elapsed_ms(&now, &last_output);
			if (poll_ms > ms)
				poll_ms = ms;
		}

		AXA_ASSERT(nfds <= AXA_DIM(pollfds));
		i = poll(pollfds, nfds, poll_ms);
		if (i < 0 && errno != EINTR)
			axa_fatal_msg(EX_OSERR, "poll(): %s", strerror(errno));

		out_flush_ck(NULL, 0);
		if (i <= 0) {
			/* Flush output to a stdio pipe when quiet. */
			if (el_e == NULL && last_output.tv_sec != 0) {
				fflush(stderr);
				fflush(stdout);
				last_output.tv_sec = 0;
			}
			continue;
		}

		/* Listen to the user before the server except when
		 * reading from a command file. */
		if (in_file_cur > 0) {
			/* Repeat anything the ssh process says */
			if (tun_nfd >= 0 && pollfds[tun_nfd].revents != 0) {
				pollfds[tun_nfd].revents = 0;
				for (;;) {
					cp = axa_io_tunerr(&client.io);
					if (cp == NULL)
					    break;
					error_msg("%s", cp);
				}
			}

			/* Process messages from the server,
			 * including TCP SYN-ACK and TLS handshaking. */
			if (i_nfd >= 0 && pollfds[i_nfd].revents != 0) {
				pollfds[i_nfd].revents = 0;
				read_srvr();
				continue;
			}
			if (o_nfd >= 0 && pollfds[o_nfd].revents != 0) {
				pollfds[o_nfd].revents = 0;
				read_srvr();
				continue;
			}
		}

		if (cmd_nfd >= 0 && pollfds[cmd_nfd].revents != 0) {
			/* in_file_cur<0 implies that
			 * pollfds[cmd_nfd] is for output.
			 * Quit when both stdin and stdout are done. */
			if (in_file_cur < 0)
				stop(EX_OK);
			break;
		}

		/* Repeat anything the ssh process says */
		if (tun_nfd >= 0 && pollfds[tun_nfd].revents != 0) {
			for (;;) {
				cp = axa_io_tunerr(&client.io);
				if (cp == NULL)
					break;
				error_msg("%s", cp);
			}
		}

		/* Process messages or TCP syn-ack from the server. */
		if (i_nfd >= 0 && pollfds[i_nfd].revents != 0)
			read_srvr();
	} while (!interrupted && !once);
}
