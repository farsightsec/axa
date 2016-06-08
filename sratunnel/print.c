/*
 * Tunnel SIE data from an SRA or RAD server.
 *
 *  Copyright (c) 2014-2016 by Farsight Security, Inc.
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

#include "sratunnel.h"

/* extern: main.c */
extern uint axa_debug;
extern int trace;

/* extern: server.c */
extern axa_client_t client;

void
print_op(bool always, bool sent, const axa_p_hdr_t *hdr, const void *body)
{
	char buf[AXA_P_STRLEN];

	if (always || axa_debug >= AXA_DEBUG_TRACE)
		axa_trace_msg("%s %s",
			      sent ? "send" : "recv",
			      axa_p_to_str(buf, sizeof(buf), true, hdr, body));
}

void
print_bad_op(const char *adj)
{
	char buf[AXA_P_STRLEN];

	axa_error_msg("recv %s%s", adj,
		      axa_p_to_str(buf, sizeof(buf), true,
				   &client.io.recv_hdr, client.io.recv_body));
}

void
print_trace(void)
{
	char buf[AXA_P_STRLEN];

	if (axa_debug > 0 || trace > 0)
		axa_trace_msg("%s", axa_p_to_str(buf,
						 sizeof(buf), false,
						 &client.io.recv_hdr,
						 client.io.recv_body));
}

void
print_missed(void)
{
	char buf[AXA_P_STRLEN];

	if (axa_debug == 0)
		return;

	axa_p_to_str(buf, sizeof(buf), true,
		     &client.io.recv_hdr,
		     client.io.recv_body);
	axa_trace_msg("%s\n",
		      axa_p_to_str(buf, sizeof(buf), true,
				   &client.io.recv_hdr, client.io.recv_body));
}
