/*
 * Advanced Exchange Access (AXA) common code for RAD and SRA clients
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

#ifndef AXA_CLIENT_H
#define AXA_CLIENT_H

/*! \file client.h
 *  \brief Common code for RAD and SRA clients
 *
 *  This file contains AXA client macros, datatypes definitions, and function
 *  prototypes.
 */

#include <axa/axa.h>
#include <axa/wire.h>

/**
 * maximum length of an AXA server specification such as "unix user@host"
 */
#define AXA_MAX_SRVRLEN (4+64+1025+1)


/**
 *  AXA client types:
 *	unix:/path/to/socket
 *	tcp:hostname,port
 *	ssh:[user@]host
 */
typedef enum {
	CLIENT_TYPE_UNKN    =0,
	CLIENT_TYPE_UNIX,
#define  CLIENT_TYPE_UNIX_STR "unix"    /**< UNIX domain socket connection */
	CLIENT_TYPE_TCP,
#define  CLIENT_TYPE_TCP_STR "tcp"      /**< TCP connection */
	CLIENT_TYPE_SSH
#define  CLIENT_TYPE_SSH_STR "ssh"      /**< connection via ssh */
} axa_client_type_t;

/** AXA client state */
typedef struct {
	axa_client_type_t type;		/**< connection type */
	bool		is_rad;		/**< server is radd instead of srad */
	bool		debug_on;	/**< enable some debugging messages */
	char		*addr;		/**< [user@]sshhost, host, path, ... */
	axa_p_user_t	user;		/**< for TCP or UNIX domain socket */
	bool		connected;	/**< false if connect() in progress */
	char		*hello;		/**< HELLO string from server */

	axa_socku_t	su;		/**< TCP/IP or UDS address of server */

	bool		have_id;	/**< for AXA_P_OP_JOIN */
	axa_p_clnt_id_t clnt_id;	/**< unquie client ID */

	axa_p_pvers_t	pvers;		/**< protocol version for this server */

	struct timeval	alive;		/**< AXA protocol keepalive timer */

	int		in_sock;	/**< input socket to server */
	int		out_sock;	/**< output socket to server */

	int		err_sock;	/**< error messages from ssh process */

	/** @cond */
	char		ebuf[120];	/**< ssh stderr buffer */
	int		ebuf_len;	/**< data data in ebuf */
	int		ebuf_bol;	/**< start of next line in ebuf */

	pid_t		ssh_pid;	/**< ssh PID for CLIENT_TYPE_SSH_STR */

	struct timeval	retry;		/**< retry timer */
	time_t		backoff;	/**< back-off quantum */
	/** @endcond */

	axa_recv_buf_t	buf;		/**< new data from server */
	axa_p_hdr_t	recv_hdr;       /**< received header */
	axa_p_body_t	*recv_body;	/**< received body */
	size_t		recv_len;	/**< sizeof(recv_hdr) + *recv_body */
} axa_client_t;

/**
 * Check than an AXA client structure is closed
 *
 *  \param[in] client address of a client structure
 */
#define AXA_CLIENT_OPENED(client) ((client)->in_sock >= 0)

/**
 * check that an AXA client structure is open and connected
 *
 *  \param[in] client address of a client structure
 */
#define AXA_CLIENT_CONNECTED(client) (AXA_CLIENT_OPENED(client)		\
				      && (client)->connected)

/**
 *  (Re-)initialize an AXA client structure with default values.
 *
 *  \param[in] client address of a client structure
 */
extern void axa_client_init(axa_client_t *client);

/**
 *  Disconnect from the server
 *  and increase the delay before trying again.
 *
 *  \param[in] client address of a client structure
 */
extern void axa_client_backoff(axa_client_t *client);

/**
 *  Disconnect from the server and increase
 *  the delay before trying again to the maximum.
 *
 *  \param[in] client address of a client structure
 */
extern void axa_client_backoff_max(axa_client_t *client);

/**
 *  Reset the delay before try to connect to zero.
 *
 *  \param[in] client address of a client structure
 */
extern void axa_client_backoff_reset(axa_client_t *client);

/**
 *  Get the number of milliseconds before the server connection should
 *  be attempted again.
 *
 *  \param[in] client address of a client structure
 *  \param[out] now current wall clock time or NULL
 *
 *  \return <= 0 if yes
 */
extern time_t axa_client_again(axa_client_t *client, struct timeval *now);

/**
 *  Flush data including applying free() to client->recv_body.
 *
 *  \param[in] client address of a client structure
 */
extern void axa_client_flush(axa_client_t *client);

/**
 *  Close the server connection and flush or release buffers.
 *
 *  \param[in] client address of a client structure
 */
extern void axa_client_close(axa_client_t *client);

/**
 *  return codes for axa_client_open() and axa_client_connect()
 */
typedef enum {
	/** permanent failure.  The connection has been closed and
	 * axa_client_backoff() called. Check emsg */
	AXA_CLIENT_CONNECT_BAD,

	/** temporary failure.  The connection has been closed and
	 * axa_client_backoff() called. Check emsg */
	AXA_CLIENT_CONNECT_TEMP,

	/** connection is complete */
	AXA_CLIENT_CONNECT_DONE,

	/** non-blocking connection still waiting for TCP syn-ack */
	AXA_CLIENT_CONNECT_INCOM,

	/** connection now completed including sending the initial
	 *  AXA_P_OP_NOP.  emsg contains the result of
	 *  axa_p_to_str(emsg->c, sizeof(emsg->c), true, ...) */
	AXA_CLIENT_CONNECT_NOP,

	/** connection now completed including sending the initial
	 *  AXA_P_OP_USER. An AXA_P_OP_OK or AXA_P_OP_ERROR should
	 * be coming.  emsg contains the result of
	 *  axa_p_to_str(emsg->c, sizeof(emsg->c), true, ...) */
	AXA_CLIENT_CONNECT_USER
} axa_client_connect_result_t;

/**
 *  Create a new server connection perhaps after closing an existing
 *	connection.  axa_client_connect() must be called after a result other
 *	than AXA_CLIENT_CONNECT_DONE, AXA_CLIENT_CONNECT_NOP,
 *	or AXA_CLIENT_CONNECT_USER.
 *
 *  \param[out] emsg if something goes wrong, this will contain the reason
 *  \param[in] client address of a client structure
 *  \param[in] is_rad true if server is radd isntead of srad
 *  \param[in] addr connect to this AXA server specification
 *  \param[in] debug_on true to turn on debugging output from libaxa without
 *	affecting tracing by the server
 *  \param[in] nonblock true to start the connection without blocking and
 *	to make the connection non-blocking
 *
 *  \retval one of #axa_client_connect_result_t
 */
extern axa_client_connect_result_t axa_client_open(axa_emsg_t *emsg,
						   axa_client_t *client,
						   const char *addr,
						   bool is_rad, bool debug_on,
						   bool nonblock);

/**
 *  Restore previously working or finish a new connection to an SRA or
 *	RAD server.  The connection must have been previously opened with
 *	axa_client_open().  axa_client_connect() must be called again
 *	after a result other than AXA_CLIENT_CONNECT_DONE,
 *	AXA_CLIENT_CONNECT_NOP, or AXA_CLIENT_CONNECT_USER.
 *
 *  \param[out] emsg if something goes wrong, this will contain the reason
 *  \param[in] client address of a client structure
 *  \param[in] nonblock true for nonblocking
 *
 *  \retval one of #axa_client_connect_result_t
 */
extern axa_client_connect_result_t axa_client_connect(axa_emsg_t *emsg,
						      axa_client_t *client,
						      bool nonblock);

/**
 *  Send an AXA message to the server connected through a client structure,
 *	blocking until finished.
 *  \param[out] emsg if something goes wrong, this will contain the reason
 *  \param[in] client address of a client structure
 *  \param[in] tag AXA tag
 *  \param[in] op AXA opcode
 *  \param[out] hdr AXA protocol header to be built or NULL
 *  \param[in] body NULL or optional body of the AXA message after the header
 *  \param[in] body_len length of body
 *
 *  \retval true success
 *  \retval false error.  Call axa_client_backoff() and check check emsg.
 */
extern bool axa_client_send(axa_emsg_t *emsg, axa_client_t *client,
			    axa_tag_t tag, axa_p_op_t op, axa_p_hdr_t *hdr,
			    const void *body, size_t body_len);

/**
 *  return codes for axa_client_recv() and axa_client_recv_wait()
 */
typedef enum {
	/** fatal error or EOF.
	 * Call axa_client_backoff() and check check emsg. */
	AXA_CLIENT_RECV_ERR,

	AXA_CLIENT_RECV_STDERR,		/**< text waiting on ssh stderr */
	AXA_CLIENT_RECV_INCOM,		/**< incomplete; poll() & try again */
	AXA_CLIENT_RECV_KEEPALIVE,	/**< need to send keepalive NOP */
	AXA_CLIENT_RECV_DONE		/**< complete message received */
} axa_client_recv_result_t;

/**
 *  Wait for some input activit.
 *
 *  \param[out] emsg if something goes wrong, this will contain the reason
 *  \param[in] client address of the client structure
 *
 *  \retval one of #axa_client_recv_result_t
 */
extern axa_client_recv_result_t
axa_client_recv_wait(axa_emsg_t *emsg, axa_client_t *client, time_t wait_ms);

/**
 *  Wait for and read an AXA message from the server into the client structure
 *
 *  \param[out] emsg if something goes wrong, this will contain the reason
 *  \param[in] client address of the client structure
 *  \param[in] wait_ms wait at least this long
 *
 *  \retval one of #axa_client_recv_result_t
 */
extern axa_client_recv_result_t axa_client_recv(axa_emsg_t *emsg,
						axa_client_t *client,
						time_t wait_ms);

/**
 *  Examine HELLO message from server to pick a common protocol version
 *  and save session information.
 *
 *  \param[out] emsg if something goes wrong, this will contain the reason
 *  \param[in] client address of the client structure
 *	default to &client->recv_body->hello if NULL
 *  \param[in] hello address of the received HELLO message or NULL, which
 *	    implies client->recv_body->hello
 *
 *  \retval true parameters saved
 *  \retval false bad HELLO
 */
extern bool axa_client_hello(axa_emsg_t *emsg, axa_client_t *client,
			     const axa_p_hello_t* hello);

/**
 *  Get anything the ssh process says to stderr.
 *
 *  \param[in] client address of the client structure
 *
 *  \retval NULL or pointer to '\0' terminated text
 */
extern const char *axa_client_stderr(axa_client_t *client);

#endif /* AXA_CLIENT_H */
