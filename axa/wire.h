/*
 * Advanced Exchange Access (AXA) send, receive, or validate SRA data
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

#ifndef AXA_WIRE_H
#define AXA_WIRE_H

/**
 *  \defgroup axa_wire axa_wire
 *
 *  `axa_wire` is an interface for wire protocol data types and function
 *  declarations.
 *
 * @{
 */

#include <axa/axa.h>
#include <axa/protocol.h>

#include <nmsg.h>

#include <openssl/ssl.h>

/**
 *  Parse an AXA watch definition.
 *  If there is a problem, the function will return false and emsg->c will
 *  contain a relevant error message -- except when the watch makes no sense.
 *  In that case, emsg->c[0] == '\0'.
 *
 *  \param[out] emsg the reason if something went wrong
 *  \param[out] watch parsed result
 *  \param[out] watch_len sizeof(*watch) - sizeof(watch->pat);
 *  \param[in] arg user specified string to watch for, must be NULL terminated
 *
 *  \retval true success
 *  \retval false error; check emsg
 */
extern bool axa_parse_watch(axa_emsg_t *emsg,
			    axa_p_watch_t *watch, size_t *watch_len,
			    const char *arg);

/**
 *  Parse a RAD watch definition.
 *  If there is a problem, the function will return false and emsg->c will
 *  contain a relevant error message -- except when the watch is unrecognized.
 *  In that case, emsg->c[0] == '\0'.
 *
 *  \param[out] emsg if something goes wrong, this will contain the reason
 *  \param[out] watch parsed result
 *  \param[out] watch_len sizeof(*watch) - sizeof(watch->pat);
 *  \param[in] arg user specified string to watch for, must be NULL terminated
 *
 *  \retval true success
 *  \retval false error, check emsg
 */
extern bool axa_parse_rad_watch(axa_emsg_t *emsg,
				axa_p_watch_t *watch, size_t *watch_len,
				const char *arg);

/**
 *  Parse an AXA anomaly detection module definition.
 *
 *  If there is a problem, the function will return false and emsg->c will
 *  contain a relevant error message -- except when the watch is unrecognized.
 *  In that case, emsg->c[0] == '\0'.
 *
 *  \param[out] emsg if something goes wrong, this will contain the reason
 *  \param[out] anom parsed result
 *  \param[out] anom_len sizeof(*watch) - sizeof(watch->pat);
 *  \param[in] arg user specified string to watch for, must be NULL terminated
 *
 *  \retval true success
 *  \retval false error, check emsg
 */
extern bool axa_parse_anom(axa_emsg_t *emsg,
			   axa_p_anom_t *anom, size_t *anom_len,
			   const char *arg);

/**
 *  Convert a network address to its string equivalent
 *
 *  \param[out] buf will hold the watch string
 *  \param[in] buf_len length of buf
 *  \param[in] af the address family
 *  \param[in] addr the address to convert
 *  \param[in] alen size of the addr parameter
 *  \param[in] prefix address prefix length
 *
 *  \return buf
 */
extern char *axa_watch_ip_to_str(char *buf, size_t buf_len,
		int af, const void *addr, size_t alen, uint prefix);

/**
 *  Convert a watch to its string equivalent
 *
 *  \param[out] buf will hold the watch string
 *  \param[in] buf_len length of buf
 *  \param[in] watch the watch to convert
 *  \param[in] watch_len size of the watch parameter
 *
 *  \return buf
 */
extern char *axa_watch_to_str(char *buf, size_t buf_len,
			      const axa_p_watch_t *watch, size_t watch_len);

/** maximum human readable tag string length */
#define AXA_TAG_STRLEN 10

/**
 *  Convert AXA tag to its string equivalent. If the tag is #AXA_TAG_NONE, buf
 *  will contain "*".
 *
 *  \param[out] buf will hold the tag string
 *  \param[in] buf_len length of buf (should be AXA_TAG_STRLEN)
 *  \param[in] tag the AXA tag value
 *
 *  \return buf
 */
extern const char *axa_tag_to_str(char *buf, size_t buf_len, axa_tag_t tag);

/** maximum buffer size for text representations of AXA opcodes */
#define AXA_P_OP_STRLEN 20

/**
 *  Convert AXA opcode to its string equivalent. If the opcode is unknown to
 *  AXA, the buffer will contain the string "unknown op n".
 *
 *  \param[out] buf will hold the opcode string
 *  \param[in] buf_len length of buf (should be #AXA_P_OP_STRLEN)
 *  \param[in] op the opcode to look up
 *
 *  \return buf
 */
extern const char *axa_op_to_str(char *buf, size_t buf_len, axa_p_op_t op);

/**
 *  Convert AXA option type to its string equivalent. If the opcode is
 *  unknown to AXA, the buffer will contain the string
 *  "unknown option type #n".
 *
 *  \param[out] buf will hold the option type string
 *  \param[in] buflen length of buf (should be #AXA_P_OP_STRLEN)
 *  \param[in] opt the option type to look up
 *
 *  \return buf
 */
extern const char * axa_opt_to_str(char *buf, size_t buflen, axa_p_opt_type_t opt);

/**
 *   Convert AXA tag and opcode to their string equivalents separated by ' '.
 *
 *  \param[out] buf for the result
 *  \param[in] buf_len length of buf (should be #AXA_P_OP_STRLEN)
 *  \param[in] tag the tag to convert
 *  \param[in] op the opcode to convert
 *
 *  \return buf
 */
extern const char *axa_tag_op_to_str(char *buf, size_t buf_len,
				     axa_tag_t tag, axa_p_op_t op);

/**
 *  Parse a raw IP datagram.
 *
 *  \param[in] pkt_data	IP datagram
 *  \param[in] caplen captured length of the packet
 *  \param[in] ch host byte order SIE channel on which it arrived
 *  \param[out] dst buffer for destination address and port number
 *  \param[out] src buffer for destination address and port number
 *  \param[out] cmt buffer for error messages, optional protocol name,or
 *	other optional comments; always '\0' terminated
 *  \param[in] cmt_len length of cmt; 80 is good
 *
 *  \retval true found something to decode into the src and dst buffers
 *  \retval false only the cmt buffer is set
 */
extern bool axa_ipdg_parse(const uint8_t *pkt_data, size_t caplen,
			   axa_p_ch_t ch, axa_socku_t *dst, axa_socku_t *src,
			   char *cmt, size_t cmt_len);


/* "dns=" *. NS_MAXDNAME AXA_P_WATCH_STR_SHARED '\0' */
/** Maximum buffer or string length from axa_p_to_str() */
#define AXA_P_STRLEN (sizeof("dns=")-1+2+1025+1				\
		      +sizeof(AXA_P_WATCH_STR_SHARED)+1)

/**
 *  Convert AXA protocol message to a string representation.
 *  Return NULL if the protocol message is invalid.
 *
 *  \param[out] buf will hold the message string
 *  \param[in] buf_len length of buf (should be AXA_P_STRLEN)
 *  \param[in] print_op if true, prepend the tag and opcode to string
 *  \param[in] hdr protocol header
 *  \param[in] cmd AXA command to parse into a string
 *
 *  \return buf
 */
extern char *axa_p_to_str(char *buf, size_t buf_len, bool print_op,
			  const axa_p_hdr_t *hdr, const axa_p_body_t *cmd);

/**
 *  AXA protocol data direction, to or from SRA or RAD server
 */
typedef enum {
	AXA_P_TO_SRA,			/**< To SRA server */
	AXA_P_FROM_SRA,			/**< From SRA server */
	AXA_P_TO_RAD,			/**< To RAD server */
	AXA_P_FROM_RAD			/**< From RAD server */
} axa_p_direction_t;

/**
 * Check the header of an AXA message.  Return false if
 * the header is invalid.
 *
 *  \param[out] emsg the reason if the return value is false
 *  \param[in] hdr AXA protocol header (will be filled in)
 *  \param[in] label label for error message
 *  \param[in] dir direction of header for error message
 *
 *  \return bool header is ok
 */
extern bool
axa_ck_hdr(axa_emsg_t *emsg, const axa_p_hdr_t *hdr,
	   const char *label, axa_p_direction_t dir);

/**
 *  Populate an AXA header including converting to wire byte order.
 *
 *  \param[out] emsg the reason if the return value is 0
 *  \param[out] hdr AXA protocol header (will be filled in)
 *  \param[in] pvers protocol version
 *  \param[in] tag AXA tag
 *  \param[in] op AXA opcode
 *  \param[in] b1_len length of first message body (if any)
 *  \param[in] b2_len length of second message body (if any)
 *  \param[in] dir the direction of the flow (to/from SRA to to/from RAD)
 *
 *  \return 0 for bad parameters or total length of AXA message or
 *	sizeof(hdr)+b1_len+b2_len in wire byte order
 */
extern size_t axa_make_hdr(axa_emsg_t *emsg, axa_p_hdr_t *hdr,
			   axa_p_pvers_t pvers, axa_tag_t tag, axa_p_op_t op,
			   size_t b1_len, size_t b2_len, axa_p_direction_t dir);

/**
 *  Sanity check the body of an AXA message
 *
 *  Depending on the opcode, function checks such things as NULL
 *  termination on strings, sane channel numbers, legal options, watch
 *  semantics, etc.
 *
 *  \param[out] emsg if something goes wrong, this will contain the reason
 *  \param[in] op opcode
 *  \param[in] body message body
 *  \param[in] body_len message body length
 *
 *  \retval true message is legal
 *  \retval false something's wrong, check emsg
 */
extern bool axa_ck_body(axa_emsg_t *emsg, axa_p_op_t op,
			const axa_p_body_t *body, size_t body_len);

/**
 *  AXA I/O type prefix: UNIX domain socket
 *  unix:/path/to/socket
 */
#define	AXA_IO_TYPE_UNIX_STR "unix"	
/**
 *  AXA I/O type prefix: TCP connection
 *  tcp:hostname,port
 */
#define AXA_IO_TYPE_TCP_STR "tcp"
/**
 *  AXA I/O type prefix: ssh connection
 *  ssh:[user\@]host
 */
#define AXA_IO_TYPE_SSH_STR "ssh"
/**
 *  AXA I/O type prefix: tls connection
 *  tls:certfile,keyfile[,certdir]\@host[,port]
 */
#define AXA_IO_TYPE_TLS_STR "tls"
/**
 *  AXA I/O type prefix: apikey/tls
 *  apikey:hostname,port
 */
#define AXA_IO_TYPE_APIKEY_STR "apikey"

/** AXA I/O context types */
typedef enum {
	AXA_IO_TYPE_UNKN = 0,		/**< invalid */
	AXA_IO_TYPE_UNIX,		/**< UNIX domain socket */
	AXA_IO_TYPE_TCP,		/**< TCP/IP socket */
	AXA_IO_TYPE_SSH,		/**< ssh pipe */
	AXA_IO_TYPE_TLS,		/**< TLS connection */
	AXA_IO_TYPE_APIKEY		/**< apikey/TLS */
} axa_io_type_t;

/** AXA I/O context */
typedef struct axa_io {
	axa_io_type_t	type;		/**< type */
	bool		is_rad;		/**< true=server is radd, not srad */
	bool		is_client;	/**< true=client instead of server */
	bool		nonblock;	/**< non-blocking I/O */

	axa_socku_t	su;		/**< peer IP or UDS address */

	/** [user@]sshhost, host,port, socket path, or whatever of peer */
	char		*addr;
	/** text to label tracing and error messages, close to addr */
	char		*label;

	int		bufsize;	/**< SO_RCVBUF and SO_SNDBUF size */
	int		i_fd;		/**< input to server */
	int		i_events;	/**< needed poll(2) events */
	int		o_fd;		/**< output from server */
	int		o_events;	/**< needed poll(2) events */

	char		*cert_file;	/**< TLS certificate file */
	char		*key_file;	/**< TLS key file name */
	SSL		*ssl;		/**< TLS OpenSSL ssl */
	char		*tls_info;	/**< TLS cipher, compression, etc. */

	axa_p_user_t    user;           /**< TLS, TCP or UNIX domain socket */
	axa_p_user_t    apikey;         /**< apikey */
	bool		connected_tcp;	/**< false if connect() in progress */
	bool		connected;	/**< TLS or other connection made */

	/**
	 *  In an AXA client using an ssh pipe and so type==CLIENT_TYPE_SSH_STR,
	 *  this FD gets error messages from ssh.  In a server, it keeps the
	 *  sshd process from closing the sshd-ssh connection.
	 */
	int		tun_fd;
	pid_t		tun_pid;	/**< ssh PID */
	bool		tun_debug;	/**< enable tunnel debugging */

	char		*tun_buf;	/**< transport error or trace buffer */
	size_t		tun_buf_size;	/**< length of tun_buf */
	size_t		tun_buf_len;	/**< data data in tun_buf */
	size_t		tun_buf_bol;	/**< start of next line in tun_buf */

	axa_p_pvers_t	pvers;		/**< protocol version for this server */

	axa_p_hdr_t	recv_hdr;       /**< received header */
	axa_p_body_t	*recv_body;	/**< received body */
	size_t		recv_body_len;	/**< sizeof(recv_hdr) + *recv_body */

	uint8_t		*recv_buf;	/**< unprocessed input data */
	ssize_t		recv_buf_len;	/**< size of recv_buf_data */
	uint8_t		*recv_start;	/**< start of unused in recv_buf_data */
	ssize_t		recv_bytes;	/**< length of unused data */

	uint8_t		*send_buf;	/**< non-blocking output buffer */
	size_t		send_buf_len;	/**< non-blocking output buffer size */
	uint8_t		*send_start;	/**< start of unsent output */
	size_t		send_bytes;	/**< number of unsent bytes */

	struct timeval	alive;		/**< AXA protocol keepalive timer */
} axa_io_t;

/**
 * Check than an AXA I/O context is open.
 *
 *  \param[in] io address of an I/O context
 */
#define AXA_IO_OPENED(io) ((io)->i_fd >= 0)

/**
 * check that an AXA I/O context is open and connected
 *
 *  \param[in] io address of an I/O context
 */
#define AXA_IO_CONNECTED(io) (AXA_IO_OPENED(io) && (io)->connected)

/**
 *  Initialize an AXA I/O structure with default values.
 *  When re-initializing, all buffers must have been freed and file descriptors
 *  closed.
 *
 *  \param[in] io address of an I/O context
 */
extern void axa_io_init(axa_io_t *io);

/**
 *  Get the current protocol version used by an AXA I/O structure.
 *
 *  \param[in] io address of an I/O context
 *  \param[out] pvers the protocol version
 */
extern void axa_io_pvers_get(axa_io_t *io, uint8_t *pvers);

/**
 *  Set the current protocol version that will be used by an AXA I/O structure.
 *  Note this function can have drastic consequences if a connection was
 *  previously established and the protocol version is changed to something
 *  the other end does not understand.
 *
 *  \param[in] io address of an I/O context
 *  \param[out] pvers the protocol version to change to
 */
extern void axa_io_pvers_set(axa_io_t *io, uint8_t pvers);

/**
 *  Flush and free the received AXA protocol message (if any) in an I/O context
 *  from a previous use of axa_recv_buf() or axa_input().
 *
 *  \param[in] io address of an I/O context
 */
extern void axa_recv_flush(axa_io_t *io);

/**
 *  Close the connection and flush and release buffers.
 *
 *  \param[in] io address of an I/O context
 */
extern void axa_io_close(axa_io_t *io);

/**  I/O result codes */
typedef enum {
	AXA_IO_ERR,			/**< print emsg */
	AXA_IO_OK,			/**< operation finished */
	AXA_IO_BUSY,			/**< incomplete; poll() & try again */
	AXA_IO_TUNERR,			/**< get text via axa_io_tunerr() */
	AXA_IO_KEEPALIVE,		/**< need to send keepalive NOP */
/*	AXA_IO_AUTHERR,			**< authentication error */
} axa_io_result_t;

/**
 *  Receive some of an AXA request or response into a fixed header buffer and
 *  a dynamic body buffer.  This function can stall until a byte is read,
 *  so call axa_io_wait() first or axa_input() instead.
 *  axa_recv_flush() must be called to discard the AXA message before
 *  another use of this function.
 *
 *  \param[out] emsg if something goes wrong, this will contain the reason
 *  \param[in] io AXA IO context
 *
 *  \retval #AXA_IO_OK	    message in io->recv_hdr, recv_body, and recv_len
 *  \retval #AXA_IO_BUSY    try again after axa_io_wait()
 *  \retval #AXA_IO_ERR	    fatal error or EOF
 */
extern axa_io_result_t axa_recv_buf(axa_emsg_t *emsg, axa_io_t *io);

/**
 *  Send an AXA request or response to the client or the server.
 *  The message is in 1, 2, or 3 parts.
 *  hdr always points to the AXA protocol header to build
 *  b1 and b1_len specify an optional second part
 *  b2 and b2_len specify the optional third part.  The second part must
 *  be present if the third part is.
 *
 *  \param[out] emsg an error message for a result of #AXA_IO_ERR
 *  \param[in] io AXA I/O context
 *  \param[in] tag AXA tag
 *  \param[in] op AXA opcode
 *  \param[out] hdr AXA protocol header to be built or NULL
 *  \param[in] b1 NULL or first part of AXA message after header
 *  \param[in] b1_len length of b1
 *  \param[in] b2 NULL or second part of the message
 *  \param[in] b2_len length of b2
 *
 *  \retval #AXA_IO_OK	    finished or output saved
 *  \retval #AXA_IO_BUSY    nothing sent; axa_io_wait() and try again
 *  \retval #AXA_IO_ERR	    fatal error
 */
extern axa_io_result_t axa_send(axa_emsg_t *emsg, axa_io_t *io,
				axa_tag_t tag, axa_p_op_t op, axa_p_hdr_t *hdr,
				const void *b1, size_t b1_len,
				const void *b2, size_t b2_len);

/**
 *  Flush the pending output buffer.
 *
 *  \param[out] emsg contains an error message for return values other than
 *	#AXA_IO_OK
 *  \param[in] io AXA I/O context
 *
 *  \retval #AXA_IO_OK	    finished
 *  \retval #AXA_IO_BUSY    incomplete; io->{i,o}_events ready for axa_io_wait()
 *  \retval #AXA_IO_ERR	    fatal error
 */
extern axa_io_result_t axa_send_flush(axa_emsg_t *emsg, axa_io_t *io);

/**
 *  Save un-transmitted data.
 *
 *  \param[in] io AXA I/O context
 *  \param[in] done bytes already handled
 *  \param[out] hdr AXA protocol header
 *  \param[in] b1 NULL or first part of AXA message after header
 *  \param[in] b1_len length of b1
 *  \param[in] b2 NULL or second part of the message
 *  \param[in] b2_len length of b2
 */
extern void axa_send_save(axa_io_t *io, size_t done, const axa_p_hdr_t *hdr,
			  const void *b1, size_t b1_len,
			  const void *b2, size_t b2_len);

/**
 *  Wait for some input activity.
 *
 *  \param[out] emsg if something goes wrong, this will contain the reason
 *  \param[in] io address of the AXA I/O context
 *  \param[in] wait_ms wait no longer than this many milliseconds
 *  \param[in] keepalive true to wake up to send a keep-alive
 *  \param[in] tun true to pay attention if possible to tunnel messages
 *
 *  \retval one of #axa_io_result_t
 */
extern axa_io_result_t axa_io_wait(axa_emsg_t *emsg, axa_io_t *io,
				      time_t wait_ms, bool keepalive, bool tun);

/**
 *  Wait for and read an AXA message from the server into the client context.
 *
 *  #axa_recv_flush() must be called to discard the AXA message in the
 *  client context before another use of this function.
 *
 *  \param[out] emsg if something goes wrong, this will contain the reason
 *  \param[in] io address of the AXA I/O context
 *  \param[in] wait_ms milliseconds to wait
 *
 *  \retval one of #axa_io_result_t
 */
extern axa_io_result_t axa_input(axa_emsg_t *emsg, axa_io_t *io,
				    time_t wait_ms);

/**
 *  Get error or debugging messages from the tunnel (e.g. ssh).
 *
 *  \param[in] io address of the AXA I/O context
 *
 *  \retval NULL or pointer to '\0' terminated text
 */
extern const char *axa_io_tunerr(axa_io_t *io);


/** @cond */

extern axa_io_type_t axa_io_type_parse(const char **addr);
extern const char *axa_io_type_to_str(axa_io_type_t type);

/* Internal functions to clean up TLS when shutting down a connection. */
extern void axa_tls_cleanup(void);
extern void axa_apikey_cleanup(void);

/* Internal function to parse "certfile,keyfile@host,port" */
extern bool axa_tls_parse(axa_emsg_t *emsg,
			  char **cert_filep, char **key_filep, char **addr,
			  const char *spec);

extern bool axa_apikey_load_and_check_key(axa_emsg_t *emsg,
			  const char *key_file, const char *cert_file);
/* Internal functions */
extern axa_io_result_t axa_tls_start(axa_emsg_t *emsg, axa_io_t *io);
extern axa_io_result_t axa_apikey_start(axa_emsg_t *emsg, axa_io_t *io);
extern void axa_tls_stop(axa_io_t *io);
extern void axa_apikey_stop(axa_io_t *io);
extern axa_io_result_t axa_tls_write(axa_emsg_t *emsg, axa_io_t *io,
				     const void *b, size_t b_len);
extern axa_io_result_t axa_tls_flush(axa_emsg_t *emsg, axa_io_t *io);
extern axa_io_result_t axa_tls_read(axa_emsg_t *emsg, axa_io_t *io);

/* Parse apikey specification. */
extern bool axa_apikey_parse(axa_emsg_t *emsg, char **addr, axa_p_user_t *u,
		const char *spec);
extern bool axa_apikey_parse_srvr(axa_emsg_t *emsg,
			  char **cert_filep, char **key_filep, char **addr,
			  const char *spec);

/** @endcond */

/**
 *  Get or set TLS certificates directory.
 *
 *  \param[out] emsg the reason if something went wrong
 *  \param[in] dir directory containing TLS certificate key files or NULL
 *
 *  \retval true success
 *  \retval false error; check emsg
 */
extern bool axa_tls_certs_dir(axa_emsg_t *emsg, const char *dir);

/**
 *  Get or set cipher list for TLS transport.
 *
 *  \param[out] emsg the reason if something went wrong
 *  \param[in] list OpenSSL format cipher list or NULL
 *
 *  \retval NULL implies an error; check emsg
 *  \retval new value if not NULL
 */
extern const char *axa_tls_cipher_list(axa_emsg_t *emsg, const char *list);

/**
 *  Get or set TLS cipher list for apikey transport.
 *
 *  \param[out] emsg the reason if something went wrong
 *  \param[in] list OpenSSL format cipher list or NULL
 *
 *  \retval NULL implies an error; check emsg
 *  \retval new value if not NULL
 */
extern const char *axa_apikey_cipher_list(axa_emsg_t *emsg,
		const char *list);

/**
 * Initialize the AXA TLS code including creating an SSL_CTX.
 *
 *  \param[out] emsg the reason if something went wrong
 *  \param[in] srvr true if running as a server.
 *  \param[in] threaded true if using pthreads.
 *
 *  \retval true success
 *  \retval false error; check emsg
 */
extern bool axa_tls_init(axa_emsg_t *emsg, bool srvr, bool threaded);

/**
 * Initialize the AXA TLS code including creating an SSL_CTX for the
 * apikey transport.
 *
 *  \param[out] emsg the reason if something went wrong
 *  \param[in] srvr true if running as a server.
 *  \param[in] threaded true if using pthreads.
 *
 *  \retval true success
 *  \retval false error; check emsg
 */
extern bool axa_apikey_init(axa_emsg_t *emsg, bool srvr, bool threaded);

/**
 *  Clean up AXA I/O functions including freeing TLS data
 */
extern void axa_io_cleanup(void);

/**@}*/

#endif /* AXA_WIRE_H */
