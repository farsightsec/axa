/*
 * Tunnel SIE data from an SRA or RAD server.
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

#include "sratunnel.h"

/* extern: main.c */
extern int count;
extern bool counting;
extern uint axa_debug;
extern int initial_count;

/* extern: output.c */
extern nmsg_output_t out_nmsg_output;
extern pcap_t *out_pcap;

/* extern: server.c */
extern axa_client_t client;

/* global */
bool out_bar_on = false;                /* true == turn output bar spinner on */

/* private */
static const char *out_bar_strs[] = {	/* pretty bar spinner */
	"|\b", "/\b", "-\b", "\\\b", "|\b", "/\b", "-\b", "\\\b"
};
static uint out_bar_idx;
#define PROGRESS_MS (1000/AXA_DIM(out_bar_strs)) /* 2 revolutions/second */
static struct timeval out_bar_time;

static void
forward_hit(axa_p_whit_t *whit, size_t whit_len)
{
	struct timeval now;
	time_t ms;

	if (out_nmsg_output != NULL) {
		out_whit_nmsg(whit, whit_len);
	} else {
		AXA_ASSERT(out_pcap != NULL);
		out_whit_pcap(whit, whit_len);
	}
	if (out_bar_on) {
		gettimeofday(&now, NULL);
		ms = axa_elapsed_ms(&now, &out_bar_time);
		if (ms >= PROGRESS_MS) {
			fflush(stderr);
			fputs(out_bar_strs[out_bar_idx], stdout);
			fflush(stdout);
			++out_bar_idx;
			out_bar_idx %= AXA_DIM(out_bar_strs);
			out_bar_time = now;
		}
	}
	if (counting && --count <= 0) {
		if (axa_debug != 0)
			axa_trace_msg("forwarded %d messages", initial_count);
		stop(0);
	}
}

/* Forward from the server to the output */
void
forward(void)
{
	axa_emsg_t emsg;

	switch (axa_recv_buf(&emsg, &client.io)) {
	case AXA_IO_OK:
		break;
	case AXA_IO_ERR:
		disconnect(true, "%s", emsg.c);
		return;
	case AXA_IO_BUSY:
		return;			/* wait for the rest */
	case AXA_IO_TUNERR:
	case AXA_IO_KEEPALIVE:
		AXA_FAIL("impossible axa_recv_buf() result");
	}

	switch ((axa_p_op_t)client.io.recv_hdr.op) {
	case AXA_P_OP_NOP:
		print_op(false, false,
			 &client.io.recv_hdr, client.io.recv_body);
		break;

	case AXA_P_OP_ERROR:
		print_bad_op("");
		disconnect(false, " ");
		return;

	case AXA_P_OP_MISSED:
	case AXA_P_OP_MISSED_RAD:
		print_missed();
		break;

	case AXA_P_OP_WHIT:
		print_op(false, false,
			 &client.io.recv_hdr, client.io.recv_body);
		forward_hit(&client.io.recv_body->whit,
			    client.io.recv_body_len
			    - sizeof(client.io.recv_hdr));
		break;

	case AXA_P_OP_AHIT:
		print_op(false, false,
			 &client.io.recv_hdr, client.io.recv_body);
		forward_hit(&client.io.recv_body->ahit.whit,
			    client.io.recv_body_len
			    - sizeof(client.io.recv_hdr)
			    - (sizeof(client.io.recv_body->ahit)
			       - sizeof(client.io.recv_body
					->ahit.whit)));
		break;

	case AXA_P_OP_OK:
		print_trace();
		break;

	case AXA_P_OP_HELLO:
	case AXA_P_OP_WLIST:
	case AXA_P_OP_ALIST:
	case AXA_P_OP_OPT:
	case AXA_P_OP_CLIST:
		print_bad_op("unexpected ");
		break;

	case AXA_P_OP_USER:
	case AXA_P_OP_JOIN:
	case AXA_P_OP_PAUSE:
	case AXA_P_OP_GO:
	case AXA_P_OP_WATCH:
	case AXA_P_OP_WGET:
	case AXA_P_OP_ANOM:
	case AXA_P_OP_AGET:
	case AXA_P_OP_STOP:
	case AXA_P_OP_ALL_STOP:
	case AXA_P_OP_CHANNEL:
	case AXA_P_OP_CGET:
	case AXA_P_OP_ACCT:
	case AXA_P_OP_RADU:
	default:
		AXA_FAIL("impossible AXA op of %d from %s",
			 client.io.recv_hdr.op, client.io.label);
	}

	axa_recv_flush(&client.io);
}
