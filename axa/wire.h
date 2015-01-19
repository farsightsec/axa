/*
 * Advanced Exchange Access (AXA) send, receive, or validate SRA data
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

#ifndef AXA_WIRE_H
#define AXA_WIRE_H

/*! \file wire.h
 *  \brief AXA wire protocol function declarations.
 *
 */


#include <axa/axa.h>
#include <axa/protocol.h>

#include <nmsg.h>

/**
 *  Parse an AXA watch definition.
 *  If there is a problem, the function will return false and emsg->c will
 *  contain a relevant error message -- except when the watch makes no sense.
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
 *  \param[in] buf_len length of buf (should be AXA_P_OP_STRLEN)
 *  \param[in] op the opcode to look up
 *
 *  \return buf
 */
extern const char *axa_op_to_str(char *buf, size_t buf_len, axa_p_op_t op);

/**
 *   Convert AXA tag and opcode to their string equivalents separated by ' '.
 *
 *  \param[out] buf for the result
 *  \param[in] buf_len length of buf (AXA_P_TAG_STRLEN+AXA_P_OP_STRLEN)
 *  \param[in] op
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
 *  \param[in] print_op if true, preprend the tag and opcode to string
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

/** AXA I/O receive buffer */
typedef struct axa_io_recv_buf {
	uint8_t		*data;		/* the buffer itself */
	ssize_t		buf_size;       /* size of buffer */
	uint8_t		*base;		/* start of unused data */
	ssize_t		data_len;       /* length of unused data */
} axa_io_recv_buf_t;

/** AXA I/O context types */
typedef enum {
	AXA_IO_TYPE_UNKN = 0,		/**< invalid */
	AXA_IO_TYPE_UNIX,		/**< UNIX domain socket */
	AXA_IO_TYPE_TCP,		/**< TCP/IP socket */
	AXA_IO_TYPE_SSH,		/**< ssh pipe */
	AXA_IO_TYPE_TLS			/**< OpenSSL connection */
} axa_io_type_t;

/** AXA I/O context */
typedef struct axa_io {
	axa_io_type_t	type;		/**< type */
	bool		is_rad;		/**< true=server is radd, not srad */
	bool		is_client;	/**< true=client instead of server */

	axa_socku_t	su;		/**< peer IP or UDS address */

	/** [user@]sshhost, host, path, or whatever of peer */
	char		*addr;

	/** text to label tracing and error messages, close to addr */
	char		*label;

	int		in_fd;		/**< input to server */
	int		out_fd;		/**< output to server */

	/**
	 *  In an AXA client using an ssh pipe and so type==CLIENT_TYPE_SSH_STR,
	 *  this FD gets error messages from ssh.  In a server, it keeps the
	 *  sshd process from closing the sshd-ssh connection.
	 */
	int		tun_fd;
	pid_t		tun_pid;	/**< ssh PID */

	char		*tun_buf;	/**< transport error or trace buffer */
	size_t		tun_buf_size;	/**< length of tun_buf */
	size_t		tun_buf_len;	/**< data data in tun_buf */
	size_t		tun_buf_bol;	/**< start of next line in tun_buf */

	axa_p_pvers_t	pvers;		/**< protocol version for this server */

	axa_p_hdr_t	recv_hdr;       /**< received header */
	axa_p_body_t	*recv_body;	/**< received body */
	size_t		recv_len;	/**< sizeof(recv_hdr) + *recv_body */

	axa_io_recv_buf_t recv_buf;	/**< unprocessed input data */

	struct timeval	alive;		/**< AXA protocol keepalive timer */
} axa_io_t;

/**
 *  (Re-)initialize an AXA I/O structure with default values.
 *  When re-initializing, all buffers must have been freed and file descriptors
 *  closed.
 *
 *  \param[in] io address of a io context
 */
extern void axa_io_init(axa_io_t *io);

/**
 *  Flush and free the received AXA protocol message (if any) in an I/O context
 *
 *  \param[in] io address of an I/O context
 */
extern void axa_io_flush(axa_io_t *io);

/**
 *  Close the connection and flush and release buffers.
 *
 *  \param[in] io address of an I/O structure
 */
extern void axa_io_close(axa_io_t *io);

/**  result codes for axa_io_recv() */
typedef enum {
	AXA_IO_RECV_ERR,		/**< fatal error or EOF */
	AXA_IO_RECV_INCOM,		/**< incomplete; poll() & try again */
	AXA_IO_RECV_DONE		/**< complete message received */
} axa_io_recv_result_t;

/*
 *  Receive an AXA request or response into a fixed
 *  header buffer and a dynamic body buffer. This function stalls until
 *  something is read, so use poll() or select().
 *
 *  \param[out] emsg if something goes wrong, this will contain the reason
 *  \param[in] io AXA IO context
 *
 *  \retval #AXA_IO_RECV_ERR	fatal error or EOF
 *  \retval #AXA_IO_RECV_INCOM	try again after select()
 *  \retval #AXA_IO_RECV_DONE	message in io->recv_hdr, io->recv_body,
 *				    and io->recv_len
 */
extern axa_io_recv_result_t axa_io_recv(axa_emsg_t *emsg, axa_io_t *io);

/**  result codes for axa_io_send() */
typedef enum {
	AXA_IO_SEND_OK,			/**< the AXA message was sent */
	AXA_IO_SEND_BUSY,		/**< only part sent--try again later */
	AXA_IO_SEND_BAD			/**< failed to send the message */
} axa_io_send_result_t;

/**
 *  Send an SRA or RAD request or response to the
 *  client or the server.  The message is in 1, 2, or 3 parts.
 *  hdr always points to the AXA protocol header to build
 *  b1 and b1_len specify an optional second part
 *  b2 and b2_len specify the optional third part.  The second part must
 *  be present if the third part is.
 *
 *  If the function returns AXA_IO_SEND_BUSY, only part of the message was sent
 *  and the caller must figure out how much of the header and each part was
 *  sent and save the unsent data.
 *
 *  \param[out] emsg contains an error message for return values other than
 *	#AXA_IO_SEND_OK
 *  \param[in] io AXA I/O context
 *  \param[in] tag AXA tag
 *  \param[in] op AXA opcode
 *  \param[out] hdr AXA protocol header to be built or NULL
 *  \param[in] b1 NULL or first part of AXA message after header
 *  \param[in] b1_len length of b1
 *  \param[in] b2 NULL or second part of the message
 *  \param[in] b2_len length of b2
 *  \param[out] donep number of sent bytes
 *
 *  \retval #AXA_IO_SEND_BUSY
 *  \retval #AXA_IO_SEND_BAD
 *  \retval #AXA_IO_SEND_OK
 */
extern axa_io_send_result_t axa_io_send(axa_emsg_t *emsg, axa_io_t *io,
					axa_tag_t tag, axa_p_op_t op,
					axa_p_hdr_t *hdr,
					const void *b1, size_t b1_len,
					const void *b2, size_t b2_len,
					size_t *donep);

/**
 *  Get anything the ssh process says to stderr.
 *
 *  \param[in] client address of the client context
 *
 *  \retval NULL or pointer to '\0' terminated text
 */
extern const char *axa_io_tunerr(axa_io_t *io);

#endif /* AXA_WIRE_H */
