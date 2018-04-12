/*
 * SIE Remote Access (SRA) ASCII tool
 *
 *  Copyright (c) 2014-2018 by Farsight Security, Inc.
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

#include "sratool.h"

/* extern: main.c */
extern axa_emsg_t emsg;
extern uint axa_debug;
extern bool quiet;
extern axa_mode_t mode;

/* global */
axa_client_t client;			/* connection to the server */

/* Send a command to the SRA or RAD server. */
int				/* 1=ok 0=failed */
srvr_send(axa_tag_t tag, axa_p_op_t op, const void *body, size_t body_len)
{
	axa_p_hdr_t hdr;
	char pbuf[AXA_P_STRLEN];

	if (!axa_client_send(&emsg, &client, tag, op, &hdr, body, body_len)) {
		error_msg("%s", emsg.c);
		return (0);
	}

	if (axa_debug >= AXA_DEBUG_TRACE) {
		clear_prompt();
		printf("send %s\n",
		       axa_p_to_str(pbuf, sizeof(pbuf), true, &hdr, body));
	}
	return (1);
}

/* There is input from the server is available,
 * progress has been made on the connection,
 * or it is time to send a NOP. */
void
read_srvr(void)
{
	uint8_t pvers;
	char buf[AXA_P_STRLEN];

	if (!AXA_CLIENT_CONNECTED(&client)) {
		switch (axa_client_connect(&emsg, &client)) {
		case AXA_CONNECT_ERR:
		case AXA_CONNECT_TEMP:
			error_msg("%s", emsg.c);
			disconnect(true);
			break;
		case AXA_CONNECT_DONE:
		case AXA_CONNECT_INCOM:
			break;
		case AXA_CONNECT_NOP:
		case AXA_CONNECT_USER:
			if (axa_debug >= AXA_DEBUG_TRACE) {
				clear_prompt();
				printf("send %s\n", emsg.c);
			}
			break;
		}

		/* Try poll() again. */
		return;
	}

	do {
		switch (axa_recv_buf(&emsg, &client.io)) {
		case AXA_IO_ERR:
			error_msg("%s", emsg.c);
			disconnect(true);
			return;
		case AXA_IO_OK:
			break;		/* deal with the input */
		case AXA_IO_BUSY:
			return;		/* wait for the rest */
		case AXA_IO_TUNERR:	/* impossible */
		case AXA_IO_KEEPALIVE:	/* impossible */
			AXA_FAIL("impossible axa_recv_buf() result");
		}

		switch ((axa_p_op_t)client.io.recv_hdr.op) {
		case AXA_P_OP_NOP:
			if (axa_debug >= AXA_DEBUG_TRACE) {
				clear_prompt();
				printf("%s\n", axa_p_to_str(buf, sizeof(buf),
							true,
							&client.io.recv_hdr,
							client.io.recv_body));
			}
			break;

		case AXA_P_OP_HELLO:
			if (!axa_client_hello(&emsg, &client, NULL,
				(mode == RAD ? "radtool" : "sratool"))) {
				error_msg("%s", emsg.c);
				disconnect(true);
				return;
			}
			if (quiet)
				break;
			clear_prompt();
			printf("%s\n", axa_p_to_str(buf, sizeof(buf), true,
						    &client.io.recv_hdr,
						    client.io.recv_body));
			axa_io_pvers_get(&client.io, &pvers);
			printf("* Using AXA protocol %d\n", pvers);
			if (mode == SRA) {
				if (strstr(client.hello, "srad") == NULL) {
					printf(
						"warning: in sra mode but it "
						"looks like we connected to a "
						"RAD server\n");
				}
			}
			else {
				if (strstr(client.hello, "radd") == NULL) {
					printf(
						"warning: in rad mode but it "
						"looks like we connected to an "
						"SRA server\n");
				}
			}
			break;

		case AXA_P_OP_OK:
			if (quiet)
				break;
			clear_prompt();
			printf("%s\n", axa_p_to_str(buf, sizeof(buf), true,
						    &client.io.recv_hdr,
						    client.io.recv_body));
			break;

		case AXA_P_OP_ERROR:
			clear_prompt();
			printf("%s\n", axa_p_to_str(buf, sizeof(buf), true,
						    &client.io.recv_hdr,
						    client.io.recv_body));
			error_close(false);
			break;

		case AXA_P_OP_MISSED:
		case AXA_P_OP_MISSED_RAD:
			clear_prompt();
			printf("%s\n",
			       axa_p_to_str(buf, sizeof(buf), true,
					    &client.io.recv_hdr,
					    client.io.recv_body));
			break;

		case AXA_P_OP_WHIT:
			print_whit(&client.io.recv_body->whit,
				   client.io.recv_body_len
				   - sizeof(client.io.recv_hdr),
				   "", "");
			break;

		case AXA_P_OP_AHIT:
			print_ahit();
			break;

		case AXA_P_OP_WLIST:
		case AXA_P_OP_ALIST:
			wlist_alist();
			break;

		case AXA_P_OP_OPT:
			clear_prompt();
			printf("%s\n", axa_p_to_str(buf, sizeof(buf), true,
						    &client.io.recv_hdr,
						    client.io.recv_body));
			break;

		case AXA_P_OP_CLIST:
			print_channel();
			break;

		case AXA_P_OP_MGMT_GETRSP:
			printf("deprecated command, please use \"stats\"\n");
			break;

		case _AXA_P_OP_STATS_RSP:
			clear_prompt();
			print_stats(&client.io.recv_body->stats_rsp,
				   client.io.recv_body_len
				   - sizeof(client.io.recv_hdr));
			break;

		case _AXA_P_OP_KILL_RSP:
			clear_prompt();
			print_kill(&client.io.recv_body->kill,
				   client.io.recv_body_len
				   - sizeof(client.io.recv_hdr));
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
		case AXA_P_OP_MGMT_GET:
		case _AXA_P_OP_STATS_REQ:
		case _AXA_P_OP_KILL_REQ:
		default:
			AXA_FAIL("impossible AXA %s from %s",
				 axa_op_to_str(buf, sizeof(buf),
					       client.io.recv_hdr.op),
				 client.io.label);
		}
		axa_recv_flush(&client.io);
	} while (client.io.recv_bytes != 0);
}

void
disconnect(bool announce)
{
	const char *cp;

	for (;;) {
		cp = axa_io_tunerr(&client.io);
		if (cp == NULL)
			break;
		error_msg("%s", cp);
	}

	if (announce && AXA_CLIENT_OPENED(&client)) {
		clear_prompt();
		printf("disconnected\n");
	}
	axa_client_close(&client);
	out_close(announce && verbose > 0);
}
