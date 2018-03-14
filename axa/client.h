/*
 * Advanced Exchange Access (AXA) common code for RAD and SRA clients
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

#ifndef AXA_CLIENT_H
#define AXA_CLIENT_H

/**
 *  \defgroup axa_client axa_client
 *
 *  `axa_client` contains AXA client macros, data type definitions, and
 *  function prototypes.
 *
 * @{
 */

#include <axa/axa.h>
#include <axa/wire.h>

/**
 * maximum length of an AXA server specification such as "unix user@host"
 */
#define AXA_MAX_SRVRLEN (4+64+1025+1)


/** @cond */
/* obsolete but retained for upward compatibility */
#define	AXA_CLIENT_TYPE_UNIX_STR    AXA_IO_TYPE_UNIX_STR
#define AXA_CLIENT_TYPE_TCP_STR	    AXA_IO_TYPE_TCP_STR
#define AXA_CLIENT_TYPE_SSH_STR	    AXA_IO_TYPE_SSH_STR
/** @endcond */

/** AXA client state */
typedef struct {
	axa_io_t	io;		        /**< I/O context */

	struct timeval	retry;		/**< connection retry timer */
	time_t		backoff;	    /**< connection back-off quantum */

	char		*hello;		    /**< HELLO string from server */

	bool		have_id;	    /**< for AXA_P_OP_JOIN */
	axa_p_clnt_id_t clnt_id;	/**< unique client ID */
} axa_client_t;

/**
 *  Check than an AXA client context is closed.
 *
 *  \param[in] client address of a client context
 */
#define AXA_CLIENT_OPENED(client) AXA_IO_OPENED(&((client)->io))

/**
 *  Check that an AXA client context is open and connected.
 *
 *  \param[in] client address of a client context
 */
#define AXA_CLIENT_CONNECTED(client) AXA_IO_CONNECTED(&((client)->io))

/**
 *  (Re-)initialize an AXA client context with default values.
 *
 *  \param[in] client address of a client context
 */
extern void axa_client_init(axa_client_t *client);

/**
 *  Disconnect from the server and increase the delay before trying again.
 *
 *  \param[in] client address of a client context
 */
extern void axa_client_backoff(axa_client_t *client);

/**
 *  Disconnect from the server and increase the delay before trying again to
 *  the maximum.
 *
 *  \param[in] client address of a client context
 */
extern void axa_client_backoff_max(axa_client_t *client);

/**
 *  Reset the delay before try to connect to zero.
 *
 *  \param[in] client address of a client context
 */
extern void axa_client_backoff_reset(axa_client_t *client);

/**
 *  Get the number of milliseconds before the server connection should be
 *  attempted again.
 *
 *  \param[in] client address of a client context
 *  \param[out] now current wall clock time or NULL
 *
 *  \return <= 0 if yes
 */
extern time_t axa_client_again(axa_client_t *client, struct timeval *now);

/**
 *  Close the server connection and release buffers.
 *
 *  \param[in] client address of a client context
 */
extern void axa_client_close(axa_client_t *client);

/** return codes for axa_client_open() and axa_client_connect() */
typedef enum {
	/**
     * Permanent failure.  The connection has been closed and
	 * axa_client_backoff() called. Check emsg.
     */
	AXA_CONNECT_ERR,

	/**
     * Temporary failure.  The connection has been closed and
	 * axa_client_backoff() called. Check emsg
     */
	AXA_CONNECT_TEMP,

	/** connection is complete */
	AXA_CONNECT_DONE,

	/** non-blocking connection waiting for TCP syn-ack or TLS handshake */
	AXA_CONNECT_INCOM,

	/**
     *  Connection now completed including sending the initial AXA_P_OP_NOP.
     *  emsg contains the result of
     *  axa_p_to_str(emsg->c, sizeof(emsg->c), true, ...)
     */
	AXA_CONNECT_NOP,

	/**
     *  Connection now completed including sending the initial AXA_P_OP_USER.
     *  An AXA_P_OP_OK or AXA_P_OP_ERROR should be coming. emsg contains the
     *  result of axa_p_to_str(emsg->c, sizeof(emsg->c), true, ...)
     */
	AXA_CONNECT_USER
} axa_connect_result_t;

/**
 *  Create a new server connection perhaps after closing an existing
 *	connection.  axa_client_connect() must be called after a result other
 *	than AXA_CONNECT_DONE, AXA_CONNECT_NOP,	or AXA_CONNECT_USER.
 *
 *  \param[out] emsg if something goes wrong, this will contain the reason
 *  \param[in] client address of a client context
 *  \param[in] is_rad true if server is radd instead of srad
 *  \param[in] addr connect to this AXA server specification
 *  \param[in] tun_debug true to turn on ssh tunnel debugging
 *  \param[in] bufsize 0 or desired socket buffer sizes
 *  \param[in] nonblock true to start the connection without blocking and
 *	to make the connection non-blocking
 *
 *  \retval one of #axa_connect_result_t
 */
extern axa_connect_result_t axa_client_open(axa_emsg_t *emsg,
					    axa_client_t *client,
					    const char *addr, bool is_rad,
					    bool tun_debug,
					    int bufsize, bool nonblock);

/**
 *  Finish a new connection to an SRA or RAD server.
 *  The connection must have been previously opened with axa_client_open(),
 *  which must have returned #AXA_CONNECT_TEMP.
 *  axa_client_connect() must be called again when it returns #AXA_CONNECT_TEMP.
 *
 *  \param[out] emsg if something goes wrong, this will contain the reason
 *  \param[in] client address of a client context
 *
 *  \retval one of #axa_connect_result_t
 */
extern axa_connect_result_t axa_client_connect(axa_emsg_t *emsg,
					       axa_client_t *client);

/**
 *  Send an AXA message to the server connected through a client context,
 *  blocking until finished.
 *
 *  \param[out] emsg if something goes wrong, this will contain the reason
 *  \param[in] client address of a client context
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
 *  Retrieve a detailed string describing the local host/config to pass to
 *  the AXA server as part of a client HELLO message.
 *
 *  \param[out] emsg if something goes wrong, this will contain the reason
 *  \param[in] origin null-terminated string containing the name of the
 *  	requesting client application or service, i.e. radtool, sratunnel, etc.
 *  \param[in] client address of the client context
 *  \param[out] out pointer to a char * that is assigned on success. Must be
 *  	freed by caller.
 *
 *  \retval true  version string was generated successfully
 *  \retval false error occurred making client HELLO string
 */
extern bool
axa_client_get_hello_string(axa_emsg_t *emsg, const char *origin,
		axa_client_t *client, char **out);

/**
 *  Examine HELLO message from server to pick a common protocol version
 *  and save session information.
 *
 *  \param[out] emsg if something goes wrong, this will contain the reason
 *  \param[in] client address of the client context
 *	default to &client->recv_body->hello if NULL
 *  \param[in] hello address of the received HELLO message or NULL, which
 *	    implies client->recv_body->hello
 *  \param[in] origin null-terminated string with name of requesting
 *  	    application, which will be sent back in a client HELLO string
 *
 *  \retval true parameters saved
 *  \retval false bad HELLO
 */
extern bool axa_client_hello(axa_emsg_t *emsg, axa_client_t *client,
			     const axa_p_hello_t* hello, const char *origin);
/**@}*/

#endif /* AXA_CLIENT_H */
