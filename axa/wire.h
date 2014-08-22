/*
 * Send, receive, or validate SRA data.
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

#include <sys/time.h>

#include <axa/axa.h>
#include <axa/protocol.h>


extern bool axa_parse_watch(axa_emsg_t *emsg,
			    axa_p_watch_t *watch, size_t *watch_len,
			    const char *arg);
extern char *axa_watch_to_str(char *buf, size_t buf_len,
			      const axa_p_watch_t *watch, size_t watch_len);
#define AXA_P_OP_STRLEN 20
extern char *axa_op_to_str(char *buf, size_t buf_len, axa_p_op_t op);
#define AXA_TAG_STRLEN 10
extern char *axa_tag_to_str(char *buf, size_t buf_len, axa_tag_t tag);
#define AXA_P_STRLEN (4+255+1)
extern char *axa_p_to_str(char *buf, size_t buf_len, bool print_op,
			  const axa_p_hdr_t *hdr, const axa_p_body_t *cmd);
typedef enum {
	AXA_P_TO_SRA,
	AXA_P_FROM_SRA,
	AXA_P_TO_RAD,
	AXA_P_FROM_RAD
} axa_p_direction_t;
typedef enum {
	AXA_P_RECV_RESULT_ERR,		/* fatal error or EOF */
	AXA_P_RECV_RESULT_INCOM,	/* try again later after select() */
	AXA_P_RECV_RESULT_DONE		/* complete message received */
} axa_p_recv_result_t;
extern axa_p_recv_result_t axa_p_recv(axa_emsg_t *emsg, int s,
				      axa_p_hdr_t *hdr, axa_p_body_t **body,
				      size_t *recv_len,
				      const char *peer, axa_p_direction_t dir,
				      struct timeval *alive);
extern size_t axa_make_hdr(axa_p_hdr_t *hdr,
			   axa_p_pvers_t pvers, axa_tag_t tag, axa_p_op_t op,
			   size_t b1_len, size_t b2_len, axa_p_direction_t dir);
typedef enum {
	AXA_P_SEND_OK,
	AXA_P_SEND_BUSY,
	AXA_P_SEND_BAD
} axa_p_send_result_t;
extern axa_p_send_result_t axa_p_send(axa_emsg_t *emsg, int s,
				      axa_p_pvers_t pvers, axa_tag_t tag,
				      axa_p_op_t op, axa_p_hdr_t *hdr,
				      const void *b1, size_t b_len1,
				      const void *b2, size_t b_len2,
				      size_t *donep,
				      const char *peer, axa_p_direction_t dir,
				      struct timeval *alive);


#endif /* AXA_WIRE_H */
