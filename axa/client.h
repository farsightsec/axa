/*
 * Common code for RAD and SRA clients
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

#ifndef AXA_CLIENT_H
#define AXA_CLIENT_H

#include <axa/axa.h>
#include <axa/protocol.h>

#define AXA_MAX_SRVRLEN (4+64+1025+1)	/* "ssh user@host" */

typedef struct {
	char		*addr;
	axa_socku_t	su;

	bool		is_ssh;
	int		ssh_argc;
	char		*ssh_argv[20];

	bool		have_id;
	axa_p_clnt_id_t clnt_id;

	axa_p_pvers_t	pvers;
	bool		pvers_known;

	struct timeval	alive;

	int		in_sock;
	int		out_sock;
	int		err_sock;

	pid_t		ssh_pid;
	bool		nonblock_connect;

	int		in_poll_nfd;
	int		err_poll_nfd;

	struct timeval	retry;
	time_t		backoff;

	axa_p_hdr_t	recv_hdr;
	axa_p_body_t	*recv_body;
	size_t		recv_len;	/* includes sizeof(recv_hdr) */
} client_t;


extern void axa_client_init(client_t *client);
extern time_t axa_client_again(client_t *client, struct timeval *now);
extern void axa_client_backoff(client_t *client);
extern void axa_client_flush(client_t *client);
extern void axa_client_close(client_t *client);
extern bool axa_client_connect(axa_emsg_t *emsg, client_t *client,
			       bool nonblock);
extern bool axa_client_open(axa_emsg_t *emsg, client_t *client,
			    const char *addr, uint debug, bool nonblock);
extern void axa_client_hello(client_t *client, const axa_p_hello_t* hello);


#endif /* AXA_CLIENT_H */
