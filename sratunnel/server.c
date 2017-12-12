/*
 * Tunnel SIE data from an SRA or RAD server.
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

#include "sratunnel.h"

/* extern: main.c */
extern uint axa_debug;
extern int trace;
extern unsigned long count_messages_sent;
extern bool first_time;
extern const char *srvr_addr;
extern axa_mode_t mode;
extern axa_cnt_t rlimit;
extern arg_t *chs;
extern arg_t *watches;
extern arg_t *anomalies;
extern double sample;

/* extern: signal.c */
extern int terminated;

/* global */
axa_client_t client;			/* Connection to the server. */

/* private */
static axa_tag_t cur_tag;

/* Send an AXA message to the server */
bool
srvr_send(axa_tag_t tag, axa_p_op_t op, const void *body, size_t body_len)
{
	axa_p_hdr_t hdr;
	char pbuf[AXA_P_STRLEN];
	axa_emsg_t emsg;

	if (axa_client_send(&emsg, &client, tag, op, &hdr, body, body_len)) {
                ++count_messages_sent;
		print_op(false, true, &hdr, body);
		return (true);
	}

	disconnect(first_time || axa_debug != 0,
		   "sending %s failed: %s",
		   axa_p_to_str(pbuf, sizeof(pbuf), true, &hdr, body),
		   emsg.c);
	return (false);
}

/* Wait for a response from the server. */
static bool				/* false=give up and re-connect */
srvr_wait_resp(axa_p_op_t resp_op,	/* look for this response */
	       axa_p_op_t orig_op)	/* to this */
{
	bool result, done;
	const char *cp;
	axa_emsg_t emsg;

	result = false;
	done = false;
	do {
		if (terminated != 0)
			stop(terminated);

		switch (axa_input(&emsg, &client.io, INT_MAX)) {
		case AXA_IO_ERR:
			if (first_time || axa_debug != 0)
				axa_error_msg("%s", emsg.c);
			goto out;
		case AXA_IO_TUNERR:
			for (;;) {
				cp = axa_io_tunerr(&client.io);
				if (cp == NULL)
					break;
				axa_error_msg("%s", cp);
			}
			continue;
		case AXA_IO_BUSY:
			continue;
		case AXA_IO_KEEPALIVE:
			if (!srvr_send(AXA_TAG_NONE, AXA_P_OP_NOP, NULL, 0))
				return (false);
			continue;
		case AXA_IO_OK:
			/* Process a message from the server. */
			break;
		default:
			AXA_FAIL("impossible axa_client_recv() result");
		}

		switch ((axa_p_op_t)client.io.recv_hdr.op) {
		case AXA_P_OP_NOP:
			print_op(false, false,
				 &client.io.recv_hdr, client.io.recv_body);
			break;

		case AXA_P_OP_HELLO:
			if (!axa_client_hello(&emsg, &client, NULL)) {
				axa_error_msg("%s", emsg.c);
			} else {
				print_op(false, false,
					 &client.io.recv_hdr,
					 client.io.recv_body);
			}
			break;

		case AXA_P_OP_OPT:
			if (resp_op == client.io.recv_hdr.op) {
				print_op(false, false,
					 &client.io.recv_hdr,
					 client.io.recv_body);
				result = true;
			} else {
				print_bad_op("unexpected ");
			}
			done = true;
			break;

		case AXA_P_OP_OK:
			if (resp_op == client.io.recv_hdr.op
			    && orig_op == client.io.recv_body->result.orig_op) {
				print_op(false, false,
					 &client.io.recv_hdr,
					 client.io.recv_body);
				result = true;
				done = true;
			} else if (client.io.recv_body->result.orig_op
				   == AXA_P_OP_OK) {
				print_trace();
			} else {
				print_bad_op("unexpected ");
			}
			break;

		case AXA_P_OP_ERROR:
			print_op(first_time, false,
				 &client.io.recv_hdr, client.io.recv_body);
			done = true;
			break;

		case AXA_P_OP_MISSED:
		case AXA_P_OP_MISSED_RAD:
			print_missed();
			break;

		case AXA_P_OP_WHIT:
		case AXA_P_OP_AHIT:
		case AXA_P_OP_WLIST:
		case AXA_P_OP_ALIST:
		case AXA_P_OP_CLIST:
			print_bad_op("unexpected ");
			break;

		case AXA_P_OP_MGMT_GETRSP:
			/* NYI */
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
		case AXA_P_OP_KILL_REQ:
		case AXA_P_OP_KILL_RSP:
		default:
			AXA_FAIL("impossible AXA op of %d from %s",
				 client.io.recv_hdr.op, client.io.label);
		}

		axa_recv_flush(&client.io);
	} while (!done);

out:
	if (!result) {
		/* Disconnect for now if we failed to get the right response. */
		out_flush();
		axa_client_backoff(&client);
	}
	return (result);
}

/* Send an AXA command to the server and wait for the response. */
static bool				/* false=give up and re-connect */
srvr_cmd(axa_tag_t tag, axa_p_op_t op, const void *b, size_t b_len,
	 axa_p_op_t resp_op)
{
	if (!srvr_send(tag, op, b, b_len)) {
		axa_client_backoff(&client);
		return (false);
	}

	return (srvr_wait_resp(resp_op, op));
}

/* (Re)connect to the server */
void
srvr_connect(void)
{
	arg_t *arg;
	axa_p_opt_t opt;
	axa_p_watch_t watch;
	size_t watch_len;
	axa_p_channel_t channel;
	axa_p_anom_t anom;
	size_t anom_len;
	axa_emsg_t emsg;
	bool res;
	const char *srvr_addr0;
	axa_p_ch_t ch;

	/* Check for config-file-specified alias first. */
	srvr_addr0 = axa_client_config_alias_chk(srvr_addr);
	srvr_addr = srvr_addr0 ? srvr_addr0 : srvr_addr;

	if (axa_debug != 0)
		axa_trace_msg("connecting to %s", srvr_addr);
	switch (axa_client_open(&emsg, &client, srvr_addr, mode == RAD,
				axa_debug > AXA_DEBUG_TRACE,
				256*1024, false)) {
	case AXA_CONNECT_ERR:
		if (axa_debug != 0 || first_time)
			axa_error_msg("%s", emsg.c);
		exit(EX_USAGE);
	case AXA_CONNECT_TEMP:
		disconnect(axa_debug != 0 || first_time,
			   "%s", emsg.c);
		return;			/* Try again after a non-fatal error. */
	case AXA_CONNECT_DONE:
		break;
	case AXA_CONNECT_INCOM:
		AXA_FAIL("impossible result from axa_client_open");
	case AXA_CONNECT_NOP:
		if (axa_debug >= AXA_DEBUG_TRACE)
			axa_trace_msg("send %s", emsg.c);
		break;
	case AXA_CONNECT_USER:
		if (axa_debug >= AXA_DEBUG_TRACE)
			axa_trace_msg("send %s", emsg.c);
		if (!srvr_wait_resp(AXA_P_OP_OK, AXA_P_OP_USER))
			return;
		break;
	}

	/* Immediately start server tracing to log the tunnel commands. */
	if (trace != 0) {
		memset(&opt, 0, sizeof(opt));
		opt.type = AXA_P_OPT_TRACE;
		opt.u.trace = AXA_H2P32(trace);
		if (!srvr_cmd(AXA_TAG_MIN, AXA_P_OP_OPT, &opt,
			      sizeof(opt) - sizeof(opt.u)
			      + sizeof(opt.u.trace),
			      AXA_P_OP_OK))
			return;
	}

	/* Set the rate limit. */
	if (rlimit != 0) {
		memset(&opt, 0, sizeof(opt));
		opt.type = AXA_P_OPT_RLIMIT;
		opt.u.rlimit.max_pkts_per_sec = AXA_H2P64(rlimit);
		opt.u.rlimit.report_secs = AXA_H2P64(AXA_RLIMIT_NA);
		opt.u.rlimit.cur_pkts_per_sec = AXA_H2P64(AXA_RLIMIT_NA);
		if (!srvr_cmd(AXA_TAG_MIN, AXA_P_OP_OPT, &opt,
			      sizeof(opt) - sizeof(opt.u)
			      + sizeof(opt.u.rlimit),
			      AXA_P_OP_OPT))
			return;
	}

	/* Set the sampling rate. */
	if (sample > 0.0) {
		memset(&opt, 0, sizeof(opt));
		opt.type = AXA_P_OPT_SAMPLE;
		opt.u.sample = AXA_H2P32(sample * AXA_P_OPT_SAMPLE_SCALE);
		if (!srvr_cmd(AXA_TAG_MIN, AXA_P_OP_OPT, &opt,
			      sizeof(opt) - sizeof(opt.u)
			      + sizeof(opt.u.sample),
			      AXA_P_OP_OPT))
			return;
	}

	/* Block watch hits until we are ready. */
	if (!srvr_cmd(AXA_TAG_MIN, AXA_P_OP_PAUSE, NULL, 0, AXA_P_OP_OK))
		return;

	/* Start the watches. */
	cur_tag = 1;
	for (arg = watches; arg != NULL; arg = arg->next) {
		if (mode == SRA)
			res = axa_parse_watch(&emsg, &watch, &watch_len,
					      arg->c);
		else
			res = axa_parse_rad_watch(&emsg, &watch, &watch_len,
						  arg->c);
		if (!res) {
			if (emsg.c[0] == '\0') {
				axa_error_msg("unrecognized \"-w %s\"", arg->c);
			} else {
				axa_error_msg("\"-w %s\": %s", arg->c, emsg.c);
			}
			exit(EX_USAGE);
		}

		if (!srvr_cmd(cur_tag, AXA_P_OP_WATCH, &watch, watch_len,
			      AXA_P_OP_OK))
			return;
		if (mode == SRA)
			++cur_tag;
	}

	/* Turn on the channels after after the watches. */
	for (arg = chs; arg != NULL; arg = arg->next) {
		ch = 0;
		memset(&channel, 0, sizeof(channel));
		if (!axa_parse_ch(&emsg, &ch, arg->c, strlen(arg->c),
				  true, true)) {
			axa_error_msg("\"-c %s\": %s", arg->c, emsg.c);
			exit(EX_USAGE);
		}
		channel.ch = ch;

		channel.on = 1;
		if (!srvr_cmd(AXA_TAG_MIN, AXA_P_OP_CHANNEL,
			      &channel, sizeof(channel), AXA_P_OP_OK))
			return;
	}

	/* Turn on the anomaly detectors. */
	for (arg = anomalies; arg != NULL; arg = arg->next) {
		if (!axa_parse_anom(&emsg, &anom, &anom_len, arg->c)) {
			if (emsg.c[0] == '\0') {
				axa_error_msg("unrecognized \"-a %s\"", arg->c);
			} else {
				axa_error_msg("\"-a %s\": %s", arg->c, emsg.c);
			}
			exit(EX_USAGE);
		}

		if (!srvr_cmd(cur_tag, AXA_P_OP_ANOM, &anom, anom_len,
			      AXA_P_OP_OK))
			return;
	}

	if (!srvr_cmd(AXA_TAG_MIN, AXA_P_OP_GO, NULL, 0, AXA_P_OP_OK))
		return;


	/* Reset connection back-off after last watch has been accepted. */
	axa_client_backoff_reset(&client);
}

void AXA_PF(2,3)
disconnect(bool complain, const char *p, ...)
{
	va_list args;

	if (complain) {
		va_start(args, p);
		axa_verror_msg(p, args);
		va_end(args);
	}

	out_flush();
	axa_client_backoff(&client);
}
