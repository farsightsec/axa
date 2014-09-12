/*
 * Advanced Exchange Access (AXA) send, receive, or validate SRA data
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

#ifndef AXA_WIRE_H
#define AXA_WIRE_H

/*! \file wire.h
 *  \brief AXA wire protocol function declarations.
 *
 */


#include <axa/axa.h>
#include <axa/protocol.h>

/**
 *  Parse an AXA watch definition.
 *  If there's a problem, the function will return false and emsg->c will 
 *  contain a relevant error message -- except when the watch makes no sense.
 *  In that case, emsg->c[0] == '\0'.
 *
 *  \param[out] emsg will hold an error message if there's a problem
 *  \param[out] watch parsed result
 *  \param[out] watch_len sizeof(*watch) - sizeof(watch->pat);
 *  \param[in] arg user specified string to watch for, must be NULL terminated
 *
 *  \return true on success, false on error
 */
extern bool axa_parse_watch(axa_emsg_t *emsg,
			    axa_p_watch_t *watch, size_t *watch_len,
			    const char *arg);

/**
 *  Parse a RAD watch definition.
 *  If there's a problem, the function will return false and emsg->c will 
 *  contain a relevant error message -- except when the watch is unrecognized.
 *  In that case, emsg->c[0] == '\0'.
 *
 *  \param[out] emsg will hold an error message if there's a problem
 *  \param[out] watch parsed result
 *  \param[out] watch_len sizeof(*watch) - sizeof(watch->pat);
 *  \param[in] arg user specified string to watch for, must be NULL terminated
 *
 *  \return true on success, false on error
 */
extern bool axa_parse_rad_watch(axa_emsg_t *emsg,
				axa_p_watch_t *watch, size_t *watch_len,
				const char *arg);

/**
 *  Parse an AXA anomaly detection module definition.
 *
 *  If there's a problem, the function will return false and emsg->c will 
 *  contain a relevant error message -- except when the watch is unrecognized.
 *  In that case, emsg->c[0] == '\0'.
 *
 *  \param[out] emsg will hold an error message if there's a problem
 *  \param[out] watch parsed result
 *  \param[out] watch_len sizeof(*watch) - sizeof(watch->pat);
 *  \param[in] arg user specified string to watch for, must be NULL terminated
 *
 *  \return true on success, false on error
 */
extern bool axa_parse_anom(axa_emsg_t *emsg,
			   axa_p_anom_t *anom, size_t *anom_len,
			   const char *arg);

/**
 *  Convert a watch to its string equivalent
 *
 *  \param[out] buf will hold the watch string
 *  \param[out] buflen length of buf
 *  \param[in] watch the watch to convert
 *  \param[out] watch_len size of the watch parameter
 *
 *  \return buf
 */
extern char *axa_watch_to_str(char *buf, size_t buf_len,
			      const axa_p_watch_t *watch, size_t watch_len);

#define AXA_P_OP_STRLEN 20
/**
 *  Convert AXA opcode to its string equivalent. If the opcode is unknown to
 *  AXA, the buffer will contain the string "unknown op n". The function can't
 *  fail.
 *
 *  \param[out] buf will hold the opcode string
 *  \param[out] buflen length of buf (should be AXA_P_OP_STRLEN)
 *  \param[out] op the opcode to look up
 *
 *  \return buf
 */
extern char *axa_op_to_str(char *buf, size_t buf_len, axa_p_op_t op);

#define AXA_TAG_STRLEN 10
/**
 *  Convert AXA tag to its string equivalent. If the tag is #AXA_TAG_NONE, buf
 *  will contain "*". The function can't fail.
 *
 *  \param[out] buf will hold the opcode string
 *  \param[out] buflen length of buf (should be AXA_TAG_STRLEN)
 *  \param[out] tag the AXA tag value
 *
 *  \return buf
 */
extern char *axa_tag_to_str(char *buf, size_t buf_len, axa_tag_t tag);

/* "dns=" *. NS_MAXDNAME AXA_P_WATCH_STR_SHARED '\0' */
#define AXA_P_STRLEN (4+2+1025+1+sizeof(AXA_P_WATCH_STR_SHARED)+1)
/**
 *  Convert AXA protocol message to its string equivalent. If the protocol
 *  message is unrecognized or has no string equivalent, NULL is returned.
 *
 *  \param[out] buf will hold the opcode string
 *  \param[out] buflen length of buf (should be AXA_P_STRLEN)
 *  \param[out] print_op if true, preprend the tag and opcode to string
 *  \param[out] hdr protocol header
 *  \param[out] cmd AXA command to parse into a string
 *
 *  \return buf
 */
extern char *axa_p_to_str(char *buf, size_t buf_len, bool print_op,
			  const axa_p_hdr_t *hdr, const axa_p_body_t *cmd);
/**
 *  AXA receive buffer
 */
typedef struct axa_recv_buf {
	uint8_t		*data;
	ssize_t		buf_size;
	uint8_t		*base;		    /**< first data here */
	ssize_t		data_len;
} axa_recv_buf_t;

/**
 *  AXA protocol direction
 *  specifies the direction of the communication
 */
typedef enum {
	AXA_P_TO_SRA,
	AXA_P_FROM_SRA,
	AXA_P_TO_RAD,
	AXA_P_FROM_RAD
} axa_p_direction_t;

/**
 *  AXA protocol receive result
 *  return codes for axa_p_recv()
 */
typedef enum {
	AXA_P_RECV_RESULT_ERR,		/**< fatal error or EOF */
	AXA_P_RECV_RESULT_INCOM,	/**< try again later after select() */
	AXA_P_RECV_RESULT_DONE		/**< complete message received */
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
 *
 *  \param[out] emsg if something goes wrong, this will contain the reason
 *  \param[in] s client input socket fd
 *  \param[in, out] hdr AXA protocol header
 *  \param[out] bodyp will contain the next AXA protocol message
 *  \param[in, out] recv_len number of bytes previously received by this
 *  function
 *  \param[in] buf optional for reducing read() system calls
 *  \param[in] peer string describing the peer such as its IP address and port
 *  \param[in] dir the direction of the flow (to/from SRA to to/from RAD)
 *  \param[out] alive if non-NULL, triggers keepalives
 *
 *  \return one of the following codes:
 *  AXA_P_RECV_RESULT_ERR   fatal error or EOF
 *  AXA_P_RECV_RESULT_INCOM try again after select() with the same args
 *  AXA_P_RECV_RESULT_DONE  complete message received in *bodyp
 *			     recv_len=sizeof(*hdr)+bytes in *bodyp
 */
extern axa_p_recv_result_t axa_p_recv(axa_emsg_t *emsg, int s,
				      axa_p_hdr_t *hdr, axa_p_body_t **body,
				      size_t *recv_len, axa_recv_buf_t *buf,
				      const char *peer, axa_p_direction_t dir,
				      struct timeval *alive);

/**
 *  Populate an AXA header.
 *
 *  \param[out] hdr AXA protocol header (will be filled in)
 *  \param[in] pvers protocol version
 *  \param[in] tag AXA tag
 *  \param[in] op AXA opcode
 *  \param[in] b1_len length of first message body (if any)
 *  \param[in] b2_len length of second message body (if any)
 *  \param[in] dir the direction of the flow (to/from SRA to to/from RAD)
 *
 *  \return size of hdr (will include sizeof(hdr) + b1_len + b2_len)
 */
extern size_t axa_make_hdr(axa_p_hdr_t *hdr,
			   axa_p_pvers_t pvers, axa_tag_t tag, axa_p_op_t op,
			   size_t b1_len, size_t b2_len, axa_p_direction_t dir);
extern bool axa_ck_body(axa_emsg_t *emsg, axa_p_op_t op,
			const axa_p_body_t *body, size_t body_len);
/**
 *  AXA protocol send result
 *  return codes for axa_p_send()
 */
typedef enum {
	AXA_P_SEND_OK,      /**< part of the message was sent */
	AXA_P_SEND_BUSY,    /**< a hard error occured when trying to send data */
	AXA_P_SEND_BAD      /**< all messages were sent */
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
 *  \param[out] emsg if something goes wrong, this will contain the reason
 *  \param[in] s client input socket fd
 *  \param[in] pvers protocol version
 *  \param[in] tag AXA tag
 *  \param[in] op AXA opcode
 *  \param[out] hdr AXA protocol header (will be filled in)
 *  \param[in] b1 optional first message body
 *  \param[in] b1_len length of first message body
 *  \param[in] b2 optional second message body
 *  \param[in] b2_len length of second message body
 *  \param[out] donep number of sent bytes
 *  \param[in] peer peer name for error messages
 *  \param[in] dir the direction of the flow (to/from SRA to to/from RAD)
 *  \param[out] alive if non-NULL, triggers keepalives
 *
 *  \return one of the following codes: AXA_P_SEND_BUSY, AXA_P_SEND_BAD,
 *  AXA_P_SEND_OK
 */
extern axa_p_send_result_t axa_p_send(axa_emsg_t *emsg, int s,
				      axa_p_pvers_t pvers, axa_tag_t tag,
				      axa_p_op_t op, axa_p_hdr_t *hdr,
				      const void *b1, size_t b_len1,
				      const void *b2, size_t b_len2,
				      size_t *donep,
				      const char *peer, axa_p_direction_t dir,
				      struct timeval *alive);


#endif /* AXA_WIRE_H */
