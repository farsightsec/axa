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
 *  Convert AXA protocol message to its string equivalent. If the protocol
 *  message is unrecognized or has no string equivalent, NULL is returned.
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

/** AXA receive buffer */
typedef struct axa_recv_buf {
	uint8_t		*data;		/**< the buffer itself */
	ssize_t		buf_size;       /**< size of buffer */
	uint8_t		*base;		/**< start of unused data */
	ssize_t		data_len;       /**< length of unused data */
} axa_recv_buf_t;

/**
 *  AXA protocol direction
 *  specifies the direction of the communication
 */
typedef enum {
	AXA_P_TO_SRA,			/**< To SRA server */
	AXA_P_FROM_SRA,			/**< From SRA server */
	AXA_P_TO_RAD,			/**< To RAD server */
	AXA_P_FROM_RAD			/**< From RAD server */
} axa_p_direction_t;

/**
 *  return codes for axa_p_recv()
 */
typedef enum {
	AXA_P_RECV_ERR,			/**< fatal error or EOF */
	AXA_P_RECV_INCOM,		/**< incomplete; poll() & try again */
	AXA_P_RECV_DONE			/**< complete message received */
} axa_p_recv_result_t;

/**
 *  Receive an AXA request or response into a fixed header buffer and
 *  a dynamic body buffer. This function stalls until something is read, so
 *  use poll() or select().
 *  On entry, hdr points to a buffer for the AXA protocol header
 *  bodyp is a pointer to a pointer to a buffer that will be allocated
 *  and filled with the next AXA protocol message.  This buffer must
 *  be freed by the caller, perhaps with axa_client_flush().
 *  recv_len is the number of bytes previously received by this function.
 *  buf is optional for reducing read() system calls.
 *  peer is a string describing the peer such as its IP address and port number
 *  direction specifies whether this is working for an AXA server or client
 *  alive is used to trigger AXA protocol keepalives
 *  If necessary, the incoming message will be will be adjusted to the current
 *  protocol version.
 *
 *  \param[out] emsg if something goes wrong, this will contain the reason
 *  \param[in] s client input socket fd
 *  \param[in, out] hdr incoming AXA protocol header
 *  \param[out] body incoming AXA protocol message
 *  \param[in, out] recv_len number of bytes previously received by this
 *	function, eventually recv_len = sizeof(*hdr) + sizeof(*bodyp)
 *  \param[in] buf axa_recv_buf_t structure for reducing input system calls
 *  \param[in] peer string describing the peer such as its IP address and port
 *  \param[in] dir axa_p_direction_t of the flow, to or from SRA or RAD.
 *  \param[out] alive set to when the last I/O happened to facilitate
 *	keepalives if not NULL.
 *
 *  \retval #AXA_P_RECV_ERR	fatal error or EOF
 *  \retval #AXA_P_RECV_INCOM	try again after select()
 *  \retval #AXA_P_RECV_DONE	complete message received in *bodyp,
 */
extern axa_p_recv_result_t axa_p_recv(axa_emsg_t *emsg, int s,
				      axa_p_hdr_t *hdr, axa_p_body_t **body,
				      size_t *recv_len, axa_recv_buf_t *buf,
				      const char *peer, axa_p_direction_t dir,
				      struct timeval *alive);

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
 *  AXA protocol send result
 *  return codes for axa_p_send()
 */
typedef enum {
	AXA_P_SEND_OK,			/**< the AXA message was sent */
	AXA_P_SEND_BUSY,		/**< only part sent--try again later */
	AXA_P_SEND_BAD			/**< failed to send the message */
} axa_p_send_result_t;

/**
 *  Send an SRA or RAD request or response to the client or the server.
 *  The message is in 1, 2, or 3 parts.
 *  hdr always points to the AXA protocol header to build
 *  b1 and b1_len specify an optional second part
 *  b2 and b2_len specify the optional third part.  The second part must
 *  be present if the third part is.
 *
 *  If the function returns AXA_P_SEND_BUSY, only part of the message was sent
 *  and the caller must figure out how much of the header and each part was
 *  sent and save the unsent data.
 *
 *  \param[out] emsg contains an error message for return values other than
 *	#AXA_P_SEND_OK
 *  \param[in] s client input socket fd
 *  \param[in] pvers protocol version for this server
 *  \param[in] tag AXA tag
 *  \param[in] op AXA opcode
 *  \param[out] hdr AXA protocol header to be built or NULL
 *  \param[in] b1 NULL or first part of AXA message after header
 *  \param[in] b1_len length of b1
 *  \param[in] b2 NULL or second part of the message
 *  \param[in] b2_len length of b2
 *  \param[out] donep number of sent bytes
 *  \param[in] peer name for error messages
 *  \param[in] dir the direction of the flow, to/from SRA to to/from RAD
 *  \param[out] alive set to time when the request or response was sent to
 *	    facilitate keepalives if not Null
 *
 *  \retval #AXA_P_SEND_BUSY
 *  \retval #AXA_P_SEND_BAD
 *  \retval #AXA_P_SEND_OK
 */
extern axa_p_send_result_t axa_p_send(axa_emsg_t *emsg, int s,
				      axa_p_pvers_t pvers, axa_tag_t tag,
				      axa_p_op_t op, axa_p_hdr_t *hdr,
				      const void *b1, size_t b1_len,
				      const void *b2, size_t b2_len,
				      size_t *donep,
				      const char *peer, axa_p_direction_t dir,
				      struct timeval *alive);

#endif /* AXA_WIRE_H */
