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
#include <axa/wire.h>

#define AXA_MAX_SRVRLEN (4+64+1025+1)	/* "unix user@host" */

typedef enum {
	CLIENT_TYPE_UNKN=0,
	CLIENT_TYPE_UNIX,
#define  CLIENT_TYPE_UNIX_STR "unix"
	CLIENT_TYPE_TCP,
#define  CLIENT_TYPE_TCP_STR "tcp"
	CLIENT_TYPE_SSH
#define  CLIENT_TYPE_SSH_STR "ssh"
} axa_client_type_t;

typedef struct {
	axa_client_type_t type;	    /** connection type: unix, tcp, ssh */
	char		*addr;	    /** [user@]sshhost, tcphost, udspath */
	axa_p_user_t	user;	    /** for TCP or unix domain socket */
	char		*hello;	    /** HELLO string from server */

	axa_socku_t	su;	    /** socket address to server */

	bool		have_id;    /** for AXA_P_OP_JOIN */
	axa_p_clnt_id_t clnt_id;    /** unquie client ID */

	axa_p_pvers_t	pvers;	    /** protocol version */

	struct timeval	alive;	    /** AXA protocol keepalive timer */

	int		in_sock;    /** input socket to server */
	int		out_sock;   /** output socket to server */
	int		err_sock;   /** error messages from ssh process */

	pid_t		ssh_pid;    /** ssh pid if .type==CLIENT_TYPE_SSH_STR */

	bool		nonblock_connect;

	int		in_poll_nfd;  /** # of input FDs for current poll() */
	int		err_poll_nfd;	/** # of output FDS for poll() */

	struct timeval	retry;
	time_t		backoff;

	axa_recv_buf_t	buf;	/** data from server to client */

	axa_p_hdr_t	recv_hdr;
	axa_p_body_t	*recv_body;
	size_t		recv_len;	/* sizeof(recv_hdr)+ *recv_body */
} axa_client_t;

/**
 *  (Re-)initialize an axa client structure with default values.
 *  \param[in] client address of a client structure
 */
extern void axa_client_init(axa_client_t *client);

/**
 *  Check to see if is it time to a client to try connecting again.
 *  \param[in] client address of a client structure
 *  \param[out] now wall clock time
 *  \return < 0 if yes
 */
extern time_t axa_client_again(axa_client_t *client, struct timeval *now);

/**
 *  Set the client's backoff timer. If the client is connected to a server,
 *  disconnect it and re-initialize it (preserving the backoff timer).
 *  \param[in] client address of a client structure
 */
extern void axa_client_backoff(axa_client_t *client);

/**
 *  Flush client recv buffers of any data.
 *  \param[in] client address of a client structure
 */
extern void axa_client_flush(axa_client_t *client);

/**
 *  Close down any possible server connections a client might hold.
 *  \param[in] client address of a client structure
 */
extern void axa_client_close(axa_client_t *client);

/**
 *  Connect, start connecting non-blocking or try to finish a non-blocking
 *  connection via TCP or a UNIX domain socket.
 *  \param[out] emsg if something goes wrong, this will contain the reason
 *  \param[in] client address of a client structure
 *  \param[in] nonblock true for nonblocking
 *
 *  \return -1=failed 0=retry 1=success
 */
extern int axa_client_connect(axa_emsg_t *emsg, axa_client_t *client,
			      bool nonblock);

/**
 *  Create server socket from specification.
 *  \param[out] emsg if something goes wrong, this will contain the reason
 *  \param[in] client address of a client structure
 *  \param[in] addr address of where to connect
 *  \param[in] debug true to turn on debug (verbose output) when using SSH
 *  \param[in] nonblock true for nonblocking
 *
 *  \return -1=failed 0=retry 1=success
 */
extern int axa_client_open(axa_emsg_t *emsg, axa_client_t *client,
			   const char *addr, bool debug, bool nonblock);

/**
 *  Examine AXA protocol HELLO from server to pick a common protocol version.
 *  \param[in] client address of a client
 *  \param[in] hello address of hello
 */
extern void axa_client_hello(axa_client_t *client, const axa_p_hello_t* hello);


#endif /* AXA_CLIENT_H */
