/*
 * Advanced Exchange Access (AXA) protocol definitions
 *
 *  Copyright (c) 2014-2017 by Farsight Security, Inc.
 *
 * This file is used outside the AXA programs.
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

#include <axa/json.h>

#ifdef HAVE_YAJL

#include <stdbool.h>
#include <stdlib.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#ifdef __linux
#include <bsd/string.h>                 /* for strlcpy() */
#define __FAVOR_BSD
#endif
#include <netinet/udp.h>
#include <netinet/tcp.h>

#include <axa/axa.h>
#include <axa/axa_endian.h>
#include <axa/fields.h>
#include <axa/strbuf.h>
#include <axa/wire.h>
#include <string.h>
#include <libmy/b64_encode.h>
#include <yajl/yajl_gen.h>

#define add_yajl_map(g) do {                                               \
	yajl_gen_status g_status;                                            \
	g_status = yajl_gen_map_open(g);                                   \
	AXA_ASSERT(g_status == yajl_gen_status_ok);                          \
} while (0)

#define close_yajl_map(g) do {                                             \
	yajl_gen_status g_status;                                            \
	g_status = yajl_gen_map_close(g);                                  \
	AXA_ASSERT(g_status == yajl_gen_status_ok);                          \
} while (0)

#define add_yajl_array(g) do {                                               \
	yajl_gen_status g_status;                                            \
	g_status = yajl_gen_array_open(g);                                   \
	AXA_ASSERT(g_status == yajl_gen_status_ok);                          \
} while (0)

#define close_yajl_array(g) do {                                             \
	yajl_gen_status g_status;                                            \
	g_status = yajl_gen_array_close(g);                                  \
	AXA_ASSERT(g_status == yajl_gen_status_ok);                          \
} while (0)

#define add_yajl_null(g) do {                                               \
	yajl_gen_status g_status;                                           \
	g_status = yajl_gen_null(g);                                        \
	AXA_ASSERT(g_status == yajl_gen_status_ok);                         \
} while (0)

#define add_yajl_bool(g, b) do {                                           \
	yajl_gen_status g_status;                                          \
	g_status = yajl_gen_bool(g, b);                                    \
	AXA_ASSERT(g_status == yajl_gen_status_ok);                        \
} while (0)

#define add_yajl_string_len(g, s, l) do {                               \
	yajl_gen_status g_status;                                       \
	g_status = yajl_gen_string(g, (const unsigned  char *) s, l);   \
	AXA_ASSERT(g_status == yajl_gen_status_ok);                     \
} while (0)

#define add_yajl_string(g, s) add_yajl_string_len((g), (s), strlen((s)))

#define add_yajl_integer(g, i) do {                                        \
	yajl_gen_status g_status;                                          \
	g_status = yajl_gen_integer(g, i);                                 \
	AXA_ASSERT(g_status == yajl_gen_status_ok);                        \
} while (0)

#define add_yajl_number_sb(g, sb) do {                                     \
	yajl_gen_status g_status;                                          \
	g_status = yajl_gen_number(g, (const char *)sb->data, strlen(sb->data)); \
	AXA_ASSERT (g_status == yajl_gen_status_ok);                       \
} while (0)

#define add_yajl_number(g, sb, i) do {                                     \
	yajl_gen_status g_status;                                          \
	axa_strbuf_reset(sb);                                              \
	axa_strbuf_append(sb, "%" PRIu64, (i));                            \
	g_status = yajl_gen_number(g, (const char *)sb->data, strlen(sb->data)); \
	AXA_ASSERT (g_status == yajl_gen_status_ok);                       \
} while (0)

static void
callback_print_yajl_axa_strbuf(void *ctx, const char *str, size_t len)
{
	struct axa_strbuf *sb = (struct axa_strbuf *) ctx;
	axa_strbuf_append(sb, "%.*s", len, str);
}

static void
add_anom(yajl_gen g, axa_p_anom_t anom, bool print_parms)
{
	add_yajl_string(g, "an");
	add_yajl_string(g, anom.an.c);

	if (print_parms) {
		add_yajl_string(g, "parms");
		add_yajl_string(g, anom.parms);
	}
}

static axa_json_res_t
add_channel(axa_emsg_t *emsg, yajl_gen g, axa_p_ch_t ch) {
	if (ch == AXA_P2H_CH(AXA_OP_CH_ALL)) {
		add_yajl_string(g, "channel");
		add_yajl_string(g, AXA_OP_CH_ALLSTR);
	} else {
		struct axa_strbuf *sb;
		sb = axa_strbuf_init();
		if (sb == NULL) {
			axa_pemsg(emsg, "could not allocate axa_strbuf");
			return (AXA_JSON_RES_MEMFAIL);
		}

		add_yajl_string(g, "channel");
		axa_strbuf_append(sb, "%s%d", AXA_OP_CH_PREFIX, ch);
		add_yajl_string(g, sb->data);
		axa_strbuf_destroy (&sb);
	}

	return (AXA_JSON_RES_SUCCESS);
}

static axa_json_res_t
add_rlimit_count(axa_emsg_t *emsg, yajl_gen g, axa_cnt_t count)
{
	if (AXA_P2H64(count) == AXA_RLIMIT_OFF)
		add_yajl_string(g, "off");
	else if (AXA_P2H64(count) == AXA_RLIMIT_NA)
		add_yajl_null(g);
	else {
		struct axa_strbuf *sb;
		sb = axa_strbuf_init();
		if (sb == NULL) {
			axa_pemsg(emsg, "could not allocate axa_strbuf");
			return (AXA_JSON_RES_MEMFAIL);
		}
		add_yajl_number(g, sb, AXA_P2H64(count));
		axa_strbuf_destroy(&sb);
	}
	return (AXA_JSON_RES_SUCCESS);
}

static void
add_watch(yajl_gen g, axa_p_watch_t *watch, size_t watch_len)
{
	char buf[AXA_P_STRLEN];
	add_yajl_string(g, "watch_type");
	switch((axa_p_watch_type_t)watch->type) {
	case AXA_P_WATCH_IPV4:
		add_yajl_string(g, "ipv4");
		break;
	case AXA_P_WATCH_IPV6:
		add_yajl_string(g, "ipv6");
		break;
	case AXA_P_WATCH_DNS:
		add_yajl_string(g, "dns");
		break;
	case AXA_P_WATCH_CH:
		add_yajl_string(g, "channel");
		break;
	case AXA_P_WATCH_ERRORS:
		add_yajl_string(g, "errors");
		break;
	} /* switch */

	add_yajl_string(g, "watch");
	add_yajl_string(g, axa_watch_to_str(buf, sizeof(buf), watch, watch_len));
}

static axa_json_res_t
add_whit(axa_emsg_t *emsg, yajl_gen g, struct axa_strbuf *yajl_sb, nmsg_input_t nmsg_input, axa_p_whit_t *whit, size_t whit_len)
{
	axa_json_res_t json_res;

	json_res = add_channel(emsg, g, whit->hdr.ch);
	if (json_res != AXA_JSON_RES_SUCCESS)
		return (json_res);

	switch (whit->hdr.type) {
	case AXA_P_WHIT_NMSG: {
		struct axa_strbuf *sb;
		nmsg_message_t msg;
		axa_w2n_res_t wres;
		nmsg_res nres;
		const char *vname, *mname;
		char *nmsg_json = NULL;
		struct tm tm;
		time_t t;
		char when[32];

		if (whit_len < sizeof(axa_p_whit_nmsg_t)) {
			axa_pemsg(emsg, "whit_len %zu < %zu", whit_len, sizeof(axa_p_whit_nmsg_t));
			return (AXA_JSON_RES_FAILURE);
		}

		wres = axa_whit2nmsg(emsg, nmsg_input, &msg, whit, whit_len);
		if (wres != AXA_W2N_RES_SUCCESS) {
			return (AXA_JSON_RES_FAILURE);
		}

		sb = axa_strbuf_init();
		if (sb == NULL) {
			axa_pemsg(emsg, "could not allocate axa_strbuf");
			return (AXA_JSON_RES_MEMFAIL);
		}

		if(AXA_P2H_IDX(whit->nmsg.hdr.field_idx) < AXA_NMSG_IDX_RSVD) {
			const char *field_name;
			nres = nmsg_message_get_field_name(msg, whit->nmsg.hdr.field_idx, &field_name);
			if (nres == nmsg_res_success) {
				add_yajl_string(g, "field");
				add_yajl_string(g, field_name);
			} else {
				add_yajl_string(g, "field_idx");
				add_yajl_integer(g, AXA_P2H_IDX(whit->nmsg.hdr.field_idx));
			}
		}

		if (AXA_P2H_IDX(whit->nmsg.hdr.val_idx) < AXA_NMSG_IDX_RSVD) {
			add_yajl_string(g, "val_idx");
			add_yajl_integer(g, AXA_P2H_IDX(whit->nmsg.hdr.val_idx));
		}

		vname = nmsg_msgmod_vid_to_vname(AXA_P2H_IDX(whit->nmsg.hdr.vid));
		if (vname != NULL) {
			add_yajl_string(g, "vname");
			add_yajl_string(g, vname);
		} else {
			add_yajl_string(g, "vid");
			add_yajl_integer(g, AXA_P2H_IDX(whit->nmsg.hdr.vid));
		}

		mname = nmsg_msgmod_msgtype_to_mname(
				AXA_P2H16(whit->nmsg.hdr.vid),
				AXA_P2H16(whit->nmsg.hdr.type));
		if (mname != NULL) {
			add_yajl_string(g, "mname");
			add_yajl_string(g, mname);
		} else {
			add_yajl_string(g, "msgtype");
			add_yajl_integer(g, AXA_P2H_IDX(whit->nmsg.hdr.type));
		}

		add_yajl_string(g, "time");
		t = AXA_P2H32(whit->nmsg.hdr.ts.tv_sec);
		gmtime_r(&t, &tm);
		strftime(when, sizeof(when), "%Y-%m-%d %T", &tm);

		axa_strbuf_reset(sb);
		axa_strbuf_append(sb, "%s.%09u", when,
				AXA_P2H32(whit->nmsg.hdr.ts.tv_nsec));
		add_yajl_string(g, sb->data);

		nres = nmsg_message_to_json(msg, &nmsg_json);
		if (nres == nmsg_res_success) {
			add_yajl_string(g, "nmsg");
			add_yajl_integer(g, 0);

			yajl_gen_clear(g);
			axa_strbuf_clip(yajl_sb, axa_strbuf_len(yajl_sb)-1);
			axa_strbuf_append(yajl_sb, "%s", nmsg_json);
			free(nmsg_json);
		}

		axa_strbuf_destroy(&sb);
		nmsg_message_destroy(&msg);

		return (AXA_JSON_RES_SUCCESS);
	}
	case AXA_P_WHIT_IP: {
		struct axa_strbuf *sb;
		struct nmsg_ipdg dg;
		nmsg_res res;
		struct tm tm;
		time_t t;
		char when[32];

		if (whit_len < sizeof(axa_p_whit_ip_t)) {
			axa_pemsg(emsg, "whit_len %zu < %zu",
					whit_len, sizeof(axa_p_whit_ip_t));
			return (AXA_JSON_RES_FAILURE);
		}

		add_yajl_string(g, "time");
		t = AXA_P2H32(whit->ip.hdr.tv.tv_sec);
		gmtime_r(&t, &tm);
		strftime(when, sizeof(when), "%Y-%m-%d %T", &tm);

		sb = axa_strbuf_init();
		if (sb == NULL) {
			axa_pemsg(emsg, "could not allocate axa_strbuf");
			return (AXA_JSON_RES_MEMFAIL);
		}
		axa_strbuf_append(sb, "%s.%06u", when,
				AXA_P2H32(whit->ip.hdr.tv.tv_usec));
		add_yajl_string(g, sb->data);
		axa_strbuf_destroy(&sb);

		res = nmsg_ipdg_parse_pcap_raw(&dg, DLT_RAW, whit->ip.b, whit_len - offsetof(axa_p_whit_ip_t, b));
		if (res != nmsg_res_success || dg.len_network == 0) {
			add_yajl_string(g, "parse_error");
			add_yajl_bool(g, true);

			return (AXA_JSON_RES_SUCCESS);
		}

		add_yajl_string(g, "af");
		switch(dg.proto_network) {
		case AF_INET: {
			struct ip *ip_hdr;
			char addr_str[INET_ADDRSTRLEN];

			add_yajl_string(g, "IPv4");

			if (dg.network != NULL && dg.len_network >= sizeof(ip_hdr)) {
				ip_hdr = (void*)dg.network;

				add_yajl_string(g, "src");
				add_yajl_string(g, inet_ntop(AF_INET, &ip_hdr->ip_src, addr_str, sizeof(addr_str)));
				add_yajl_string(g, "dst");
				add_yajl_string(g, inet_ntop(AF_INET, &ip_hdr->ip_dst, addr_str, sizeof(addr_str)));

				add_yajl_string(g, "ttl");
				add_yajl_integer(g, ip_hdr->ip_ttl);
			}
			break;
		}
		case AF_INET6: {
			struct ip6_hdr *ip6_hdr;
			char addr_str[INET6_ADDRSTRLEN];
			
			add_yajl_string(g, "IPv6");

			if (dg.network != NULL && dg.len_network >= sizeof(ip6_hdr)) {
				ip6_hdr = (void*)dg.network;

				add_yajl_string(g, "src");
				add_yajl_string(g, inet_ntop(AF_INET6, &ip6_hdr->ip6_src, addr_str, sizeof(addr_str)));

				add_yajl_string(g, "dst");
				add_yajl_string(g, inet_ntop(AF_INET6, &ip6_hdr->ip6_dst, addr_str, sizeof(addr_str)));

				add_yajl_string(g, "ttl");
				add_yajl_integer(g, ip6_hdr->ip6_hlim);

			}
			break;
		}
		default:
			add_yajl_integer(g, dg.proto_network);
			return (AXA_JSON_RES_SUCCESS);
		} /* switch */

		add_yajl_string(g, "proto");
		switch(dg.proto_transport) {
		case IPPROTO_ICMP:
			add_yajl_string(g, "ICMP");
			break;
		case IPPROTO_ICMPV6:
			add_yajl_string(g, "ICMPv6");
			break;
		case IPPROTO_TCP:
			add_yajl_string(g, "TCP");
			if (dg.transport != NULL && dg.len_transport >= sizeof(struct tcphdr)) {
				struct tcphdr *tcp_hdr = (void*)dg.transport;

				add_yajl_string(g, "src_port");
				add_yajl_integer(g, ntohs(tcp_hdr->th_sport));

				add_yajl_string(g, "dst_port");
				add_yajl_integer(g, ntohs(tcp_hdr->th_dport));

				add_yajl_string(g, "flags");
				add_yajl_array(g);
				if ((tcp_hdr->th_flags & TH_FIN) != 0)
					add_yajl_string(g, "FIN");
				if ((tcp_hdr->th_flags & TH_SYN) != 0)
					add_yajl_string(g, "SYN");
				if ((tcp_hdr->th_flags & TH_ACK) != 0)
					add_yajl_string(g, "ACK");
				if ((tcp_hdr->th_flags & TH_RST) != 0)
					add_yajl_string(g, "RST");
				close_yajl_array(g);
			}
			break;
		case IPPROTO_UDP:
			add_yajl_string(g, "UDP");
			if (dg.transport != NULL && dg.len_transport >= sizeof(struct udphdr)) {
				struct udphdr *udp_hdr = (void*)dg.transport;

				add_yajl_string(g, "src_port");
				add_yajl_integer(g, ntohs(udp_hdr->uh_sport));

				add_yajl_string(g, "dst_port");
				add_yajl_integer(g, ntohs(udp_hdr->uh_dport));

			}
			break;
		default:
			add_yajl_integer(g, dg.proto_transport);
			break;
		} /* switch */

		if (dg.payload != NULL) {
			base64_encodestate b64;
			char *b64_str;
			size_t b64_str_len;

			base64_init_encodestate(&b64);
			b64_str = alloca(2 * dg.len_payload + 1);
			AXA_ASSERT(b64_str != NULL);

			b64_str_len = base64_encode_block((void*)dg.payload,
					dg.len_payload, b64_str, &b64);
			b64_str_len += base64_encode_blockend(b64_str + b64_str_len, &b64);

			add_yajl_string(g, "payload");
			add_yajl_string_len(g, b64_str, b64_str_len);
		}

		return (AXA_JSON_RES_SUCCESS);
	}
	default:
		axa_pemsg(emsg, "unknown whit hdr type: %d", whit->hdr.type);
		return (AXA_JSON_RES_FAILURE);
	}
}

axa_json_res_t
axa_body_to_json(axa_emsg_t *emsg, nmsg_input_t nmsg_input, axa_p_hdr_t *hdr, axa_p_body_t *body, size_t body_len, char **out)
{
	struct axa_strbuf *sb = NULL, *sb_tmp = NULL;
	axa_json_res_t res;
	yajl_gen g = NULL;
	int yajl_rc;
	char op_str[AXA_P_OP_STRLEN];
	char addr_str[INET6_ADDRSTRLEN];
	axa_p_direction_t dir;
	uint8_t *p, *q;
	uint16_t user_objs_cnt, an_objs_cnt;
	bool have_user_objs = false, have_an_objs = false;
	_axa_p_stats_sys_t *sys;
	char time_buf[30];
	struct tm *tm_info;
	time_t t;
	runits_t ru;

	switch(AXA_P2H16(hdr->op)) {
	case AXA_P_OP_MISSED_RAD:
	case AXA_P_OP_AHIT:
	case AXA_P_OP_ALIST:
		dir = AXA_P_FROM_RAD;
		break;
	case AXA_P_OP_USER:
	case AXA_P_OP_JOIN:
	case AXA_P_OP_PAUSE:
	case AXA_P_OP_GO:
	case AXA_P_OP_WATCH:
	case AXA_P_OP_WGET:
	case AXA_P_OP_STOP:
	case AXA_P_OP_ALL_STOP:
	case AXA_P_OP_CHANNEL:
	case AXA_P_OP_CGET:
	case AXA_P_OP_ACCT:
	case _AXA_P_OP_KILL_REQ:
	case _AXA_P_OP_STATS_REQ:
		dir = AXA_P_TO_SRA;
		break;
	case AXA_P_OP_ANOM:
	case AXA_P_OP_AGET:
	case AXA_P_OP_RADU:
		dir = AXA_P_TO_RAD;
		break;
	default:
		dir = AXA_P_FROM_SRA;
		break;
	} /* switch */

	if (axa_ck_hdr(emsg, hdr, "json", dir) == false)
		return (AXA_JSON_RES_FAILURE);

	if (AXA_P2H32(hdr->len) - sizeof(axa_p_hdr_t) != body_len) {
		axa_pemsg(emsg, "body length mismatch %zu != %zu",
				AXA_P2H32(hdr->len) - sizeof(axa_p_hdr_t),
				body_len);
		return (AXA_JSON_RES_FAILURE);
	}

	if (axa_ck_body(emsg, hdr->op, body, body_len) == false)
		return (AXA_JSON_RES_FAILURE);

	sb = axa_strbuf_init();
	if (sb == NULL) {
		axa_pemsg(emsg, "could not allocate axa_strbuf");
		return (AXA_JSON_RES_MEMFAIL);
	}

	sb_tmp = axa_strbuf_init();
	if (sb_tmp == NULL) {
		axa_pemsg(emsg, "could not allocate axa_strbuf");
		axa_strbuf_destroy(&sb);
		res = AXA_JSON_RES_MEMFAIL;
		goto err;
	}

	g = yajl_gen_alloc(NULL);
	AXA_ASSERT (g != NULL);

	yajl_rc = yajl_gen_config(g,
				  yajl_gen_print_callback,
				  callback_print_yajl_axa_strbuf,
				  sb);
	AXA_ASSERT(yajl_rc != 0);

	add_yajl_map(g);

	add_yajl_string(g, "tag");
	if (AXA_P2H16(hdr->tag) == AXA_TAG_NONE)
		add_yajl_string(g, "*");
	else
		add_yajl_integer(g, AXA_P2H16(hdr->tag));


	add_yajl_string(g, "op");
	axa_op_to_str(op_str, sizeof(op_str), hdr->op);
	add_yajl_string(g, op_str);

	switch ((axa_p_op_t)hdr->op) {
	case AXA_P_OP_NOP:
		break;

	case AXA_P_OP_HELLO:
		add_yajl_string(g, "id");
		add_yajl_number(g, sb_tmp, AXA_P2H64(body->hello.id));

		add_yajl_string(g, "pvers_min");
		add_yajl_integer(g, body->hello.pvers_min);

		add_yajl_string(g, "pvers_max");
		add_yajl_integer(g, body->hello.pvers_max);

		add_yajl_string(g, "str");
		add_yajl_string(g, body->hello.str);
		break;

	case AXA_P_OP_OK:
	case AXA_P_OP_ERROR:
		add_yajl_string(g, "orig_op");
		axa_op_to_str(op_str, sizeof(op_str), body->result.orig_op);
		add_yajl_string(g, op_str);

		add_yajl_string(g, "str");
		add_yajl_string(g, body->result.str);
		break;

	case AXA_P_OP_MISSED:
		add_yajl_string(g, "missed");
		add_yajl_number(g, sb_tmp, AXA_P2H64(body->missed.missed));

		add_yajl_string(g, "dropped");
		add_yajl_number(g, sb_tmp, AXA_P2H64(body->missed.dropped));

		add_yajl_string(g, "rlimit");
		add_yajl_number(g, sb_tmp, AXA_P2H64(body->missed.rlimit));

		add_yajl_string(g, "filtered");
		add_yajl_number(g, sb_tmp, AXA_P2H64(body->missed.filtered));

		add_yajl_string(g, "last_report");
		add_yajl_integer(g, AXA_P2H32(body->missed.last_report));
		break;

	case AXA_P_OP_MISSED_RAD:
		add_yajl_string(g, "sra_missed");
		add_yajl_number(g, sb_tmp, AXA_P2H64(body->missed_rad.sra_missed));

		add_yajl_string(g, "sra_dropped");
		add_yajl_number(g, sb_tmp, AXA_P2H64(body->missed_rad.sra_dropped));

		add_yajl_string(g, "sra_rlimit");
		add_yajl_number(g, sb_tmp, AXA_P2H64(body->missed_rad.sra_rlimit));

		add_yajl_string(g, "sra_filtered");
		add_yajl_number(g, sb_tmp, AXA_P2H64(body->missed_rad.sra_filtered));

		add_yajl_string(g, "dropped");
		add_yajl_number(g, sb_tmp, AXA_P2H64(body->missed_rad.dropped));

		add_yajl_string(g, "rlimit");
		add_yajl_number(g, sb_tmp, AXA_P2H64(body->missed_rad.rlimit));

		add_yajl_string(g, "filtered");
		add_yajl_number(g, sb_tmp, AXA_P2H64(body->missed_rad.filtered));

		add_yajl_string(g, "last_report");
		add_yajl_integer(g, AXA_P2H32(body->missed_rad.last_report));
		break;

	case AXA_P_OP_WHIT:
		res = add_whit(emsg, g, sb, nmsg_input, &(body->whit), body_len);
		if (res != AXA_JSON_RES_SUCCESS)
			goto err;
		break;

	case AXA_P_OP_WATCH:
		add_watch(g, &(body->watch), body_len);
		break;

	case AXA_P_OP_ANOM: {
		bool print_parms;
		print_parms = body_len > offsetof(axa_p_anom_t, parms) && body->anom.parms[0] != '\0';
		add_anom(g, body->anom, print_parms);
		break;
	}

	case AXA_P_OP_CHANNEL:
		res = add_channel(emsg, g, body->channel.ch);
		if (res != AXA_JSON_RES_SUCCESS)
			goto err;

		add_yajl_string(g, "on");
		add_yajl_bool(g, body->channel.on != 0);
		break;

	case AXA_P_OP_WLIST:
		add_yajl_string(g, "cur_tag");
		add_yajl_integer(g, AXA_P2H16(body->wlist.cur_tag));

		add_watch(g, &(body->wlist.w), body_len - offsetof(axa_p_wlist_t, w));
		break;

	case AXA_P_OP_AHIT:
		add_yajl_string(g, "an");
		add_yajl_string(g, body->ahit.an.c);

		res = add_whit(emsg, g, sb, nmsg_input, &(body->ahit.whit), body_len - offsetof(axa_p_ahit_t, whit));
		if (res != AXA_JSON_RES_SUCCESS)
			goto err;
		break;

	case AXA_P_OP_ALIST: {
		bool print_parms;
		add_yajl_string(g, "cur_tag");
		add_yajl_integer(g, AXA_P2H16(body->alist.cur_tag));

		print_parms = body_len > offsetof(axa_p_alist_t, anom) + offsetof(axa_p_anom_t, parms) && body->alist.anom.parms[0] != '\0';
		add_anom(g, body->alist.anom, print_parms);
		break;
	}

	case AXA_P_OP_CLIST:
		res = add_channel(emsg, g, body->clist.ch);
		if (res != AXA_JSON_RES_SUCCESS)
			goto err;

		add_yajl_string(g, "on");
		add_yajl_bool(g, body->clist.on != 0);

		add_yajl_string(g, "spec");
		add_yajl_string(g, body->clist.spec.c);
		break;

	case AXA_P_OP_USER:
		add_yajl_string(g, "name");
		add_yajl_string(g, body->user.name);
		break;

	case AXA_P_OP_OPT: {
		char buf[AXA_P_OP_STRLEN];

		add_yajl_string(g, "type");
		add_yajl_string(g, axa_opt_to_str(buf, sizeof(buf), AXA_P2H64(body->opt.type)));

		switch((axa_p_opt_type_t)body->opt.type) {
			case AXA_P_OPT_TRACE: {
				add_yajl_string(g, "trace");
				if (AXA_P2H64(body->opt.u.trace) != AXA_P_OPT_TRACE_REQ) {
					add_yajl_number(g, sb_tmp, AXA_P2H64(body->opt.u.trace));
				} else {
					add_yajl_string(g, "REQUEST TRACE VALUE");
				}
				break;
			}

			case AXA_P_OPT_RLIMIT:
				add_yajl_string(g, "max_pkts_per_sec");
				res = add_rlimit_count(emsg, g, body->opt.u.rlimit.max_pkts_per_sec);
				if (res != AXA_JSON_RES_SUCCESS)
					goto err;

				add_yajl_string(g, "cur_pkts_per_sec");
				add_yajl_number(g, sb_tmp, AXA_P2H64(body->opt.u.rlimit.cur_pkts_per_sec));

				add_yajl_string(g, "report_secs");
				res = add_rlimit_count(emsg, g, body->opt.u.rlimit.report_secs);
				if (res != AXA_JSON_RES_SUCCESS)
					goto err;
				break;

			case AXA_P_OPT_SAMPLE:
				add_yajl_string(g, "sample");
				if (AXA_P2H64(body->opt.u.sample) == 0) {
					add_yajl_string(g, "requested");
				} else {
					axa_strbuf_reset(sb_tmp);
					axa_strbuf_append(sb_tmp, "%0.6f", ((double)AXA_P2H64(body->opt.u.sample)) / AXA_P_OPT_SAMPLE_MAX);
					add_yajl_number_sb(g, sb_tmp);
				}
				break;

			case AXA_P_OPT_SNDBUF:
				add_yajl_string(g, "bufsize");
				add_yajl_number(g, sb_tmp, AXA_P2H64(body->opt.u.bufsize));
				break;
		} /* switch */
		break;
	}

	case AXA_P_OP_JOIN:
		add_yajl_string(g, "id");
		add_yajl_number(g, sb_tmp, AXA_P2H64(body->join.id));
		break;

	case _AXA_P_OP_STATS_REQ:
		if (body->stats_req.version != _AXA_STATS_VERSION_ONE) {
			res = AXA_JSON_RES_FAILURE;
			goto err;
		}
		add_yajl_string(g, "version");
		add_yajl_integer(g, _AXA_STATS_VERSION_ONE);

		add_yajl_string(g, "type");
		switch (body->stats_req.type) {
			case AXA_P_STATS_M_M_SUM:
				add_yajl_string(g, "summary");
				break;
			case AXA_P_STATS_M_M_ALL:
				add_yajl_string(g, "all");
				break;
			case AXA_P_STATS_M_M_SN:
				add_yajl_string(g, "serial number");
				break;
			case AXA_P_STATS_M_M_U:
				add_yajl_string(g, "user name");
				break;
			default:
				add_yajl_string(g, "unknown");
		}

		if (body->stats_req.type == AXA_P_STATS_M_M_SN) {
			add_yajl_string(g, "serial number");
			add_yajl_integer(g, body->stats_req.sn);
		}

		if (body->stats_req.type == AXA_P_STATS_M_M_U) {
			add_yajl_string(g, "user name");
			add_yajl_string(g, body->stats_req.user.name);
		}

		break;

	case _AXA_P_OP_STATS_RSP:
		if (body->stats_rsp.version != _AXA_STATS_VERSION_ONE) {
			res = AXA_JSON_RES_FAILURE;
			goto err;
		}

		if (body->stats_rsp.sys_objs_cnt > 1) {
			res = AXA_JSON_RES_FAILURE;
			goto err;
		}

		add_yajl_string(g, "result");
		switch (body->stats_rsp.result) {
			case AXA_P_STATS_R_SUCCESS:
				add_yajl_string(g, "success");
				break;
			case AXA_P_STATS_R_FAIL_NF:
				add_yajl_string(g, "failed: user not found");
				break;
			case AXA_P_STATS_R_FAIL_UNK:
			default:
				add_yajl_string(g, "failed: unknown reason");
		}

		if (body->stats_rsp.sys_objs_cnt == 1) {
			p = (uint8_t *)&body->stats_rsp;
			sys = (_axa_p_stats_sys_t *)(p +
					sizeof (_axa_p_stats_rsp_t));

			if (sys->type != _AXA_P_STATS_TYPE_SYS) {
				res = AXA_JSON_RES_FAILURE;
				goto err;
			}

			add_yajl_string(g, "load");
			add_yajl_array(g);
			add_yajl_integer(g, AXA_P2H32(sys->load[0]));
			add_yajl_integer(g, AXA_P2H32(sys->load[1]));
			add_yajl_integer(g, AXA_P2H32(sys->load[2]));
			close_yajl_array(g);

			add_yajl_string(g, "cpu_usage");
			add_yajl_integer(g, AXA_P2H32(sys->cpu_usage));

			add_yajl_string(g, "uptime");
			add_yajl_integer(g, AXA_P2H32(sys->uptime));

			add_yajl_string(g, "starttime");
			add_yajl_integer(g, AXA_P2H32(sys->starttime));

			add_yajl_string(g, "vmsize");
			add_yajl_number(g, sb_tmp, AXA_P2H64(sys->vmsize));

			add_yajl_string(g, "vmrss");
			add_yajl_number(g, sb_tmp, AXA_P2H64(sys->vmrss));

			add_yajl_string(g, "thread_cnt");
			add_yajl_integer(g, AXA_P2H32(sys->thread_cnt));

			add_yajl_string(g, "user_cnt");
			add_yajl_integer(g, AXA_P2H32(sys->user_cnt));

			switch (sys->server_type) {
				case _AXA_STATS_SRVR_TYPE_SRA:
					add_yajl_string(g, "server_type");
					add_yajl_string(g, "srad");
					add_yajl_string(g, "fd_sockets");
					add_yajl_integer(g,
						AXA_P2H32(sys->fd_sockets));

					add_yajl_string(g, "fd_pipes");
					add_yajl_integer(g,
						AXA_P2H32(sys->fd_pipes));

					add_yajl_string(g, "fd_anon_inodes");
					add_yajl_integer(g,
						AXA_P2H32(sys->fd_anon_inodes));

					add_yajl_string(g, "fd_other");
					add_yajl_integer(g,
						AXA_P2H32(sys->fd_other));

					add_yajl_string(g, "rchar");
					add_yajl_number(g, sb_tmp,
						AXA_P2H64(sys->rchar));

					add_yajl_string(g, "wchar");
					add_yajl_number(g, sb_tmp,
						AXA_P2H64(sys->wchar));

					add_yajl_string(g,
							"sra_ipv4_watch_cnt");
					add_yajl_integer(g,
						AXA_P2H32(sys->srvr.sra.watches.ipv4_cnt));
					add_yajl_string(g,
							"sra_ipv6_watch_cnt");
					add_yajl_integer(g,
						AXA_P2H32(sys->srvr.sra.watches.ipv6_cnt));
					add_yajl_string(g,
							"sra_dns_watch_cnt");
					add_yajl_integer(g,
						AXA_P2H32(sys->srvr.sra.watches.dns_cnt));
					add_yajl_string(g,
							"sra_ch_watch_cnt");
					add_yajl_integer(g,
						AXA_P2H32(sys->srvr.sra.watches.ch_cnt));
					add_yajl_string(g,
							"sra_err_watch_cnt");
					add_yajl_integer(g,
						AXA_P2H32(sys->srvr.sra.watches.err_cnt));

					add_yajl_string(g, "sra_channels");
					add_yajl_array(g);
					for (int j = 0; j < 256; j++) {
						if (axa_get_bitwords(sys->srvr.sra.ch_mask.m, j)) {
							axa_strbuf_reset(sb_tmp);
							axa_strbuf_append(sb_tmp, "ch%d", (j));
							add_yajl_string(g, (const char*)sb_tmp->data);
						}
					}
					close_yajl_array(g);
					break;
				case _AXA_STATS_SRVR_TYPE_RAD:
					add_yajl_string(g, "server_type");
					add_yajl_string(g, "radd");
					add_yajl_string(g, "rad_anomaly_cnt");
					add_yajl_integer(g,
						AXA_P2H32(sys->srvr.rad.an_cnt));
					break;
				default:
					res = AXA_JSON_RES_FAILURE;
					goto err;
			}
		}

		user_objs_cnt = body->stats_rsp.user_objs_cnt;
		p = (uint8_t *)&body->stats_rsp +
			sizeof (_axa_p_stats_rsp_t) +
			body->stats_rsp.sys_objs_cnt *
			sizeof (_axa_p_stats_sys_t);
		if (user_objs_cnt > 0) {
			have_user_objs = true;
			add_yajl_string(g, "users");
			add_yajl_array(g);
			_axa_p_stats_user_t *user_obj =
				(_axa_p_stats_user_t *)p;
			for (; user_objs_cnt; user_objs_cnt--, user_obj++) {
				add_yajl_string(g, "user_obj");
				add_yajl_map(g);

				add_yajl_string(g, "server_type");
				switch (user_obj->server_type) {
					case _AXA_STATS_SRVR_TYPE_SRA:
						add_yajl_string(g, "sra");
						break;
					case _AXA_STATS_SRVR_TYPE_RAD:
						add_yajl_string(g, "rad");
						break;
					default:
						add_yajl_string(g,
								"unkwn");
						break;
				}
				add_yajl_string(g, "user");
				add_yajl_string(g, user_obj->user.name);
				add_yajl_string(g, "is_admin");
				add_yajl_bool(g, user_obj->is_admin == 1 ?
						true : false);

				add_yajl_string(g, "io_type");
				switch (user_obj->io_type) {
					case AXA_IO_TYPE_UNIX:
						add_yajl_string(g,
							AXA_IO_TYPE_UNIX_STR);
						break;
					case AXA_IO_TYPE_TCP:
						add_yajl_string(g,
							AXA_IO_TYPE_TCP_STR);
						break;
					case AXA_IO_TYPE_SSH:
						add_yajl_string(g,
							AXA_IO_TYPE_SSH_STR);
						break;
					case AXA_IO_TYPE_TLS:
						add_yajl_string(g,
							AXA_IO_TYPE_TLS_STR);
						break;
					case AXA_IO_TYPE_APIKEY:
						add_yajl_string(g,
							AXA_IO_TYPE_APIKEY_STR);
						break;
					case AXA_IO_TYPE_UNKN:
					default:
						add_yajl_string(g, "unknown");
						break;
				}
				add_yajl_string(g, "address");
				switch (user_obj->addr_type) {
					case AXA_AF_INET:
						inet_ntop(AF_INET, &user_obj->ip.ipv4,
							addr_str, sizeof(addr_str));
						break;
					case AXA_AF_INET6:
						inet_ntop(AF_INET6, &user_obj->ip.ipv6,
							addr_str, sizeof(addr_str));
						break;
					case AXA_AF_UNKNOWN:
						strlcpy(addr_str, "unknown",
							sizeof(addr_str));
						break;
				}
				add_yajl_string(g, addr_str);
				add_yajl_string(g, "sn");
				add_yajl_integer(g, user_obj->sn);
				add_yajl_string(g, "connected_since");
				t = AXA_P2H32(user_obj->connected_since.tv_sec);
				tm_info = gmtime(&t);
				strftime(time_buf, sizeof (time_buf),
						"%Y-%m-%dT%H:%M:%SZ",
						tm_info);
				add_yajl_string(g, time_buf);
				add_yajl_string(g, "ratelimit");
				if (AXA_P2H64(user_obj->ratelimit) == AXA_RLIMIT_OFF) {
					add_yajl_integer(g, 0);
				}
				else {
					add_yajl_integer(g,
						AXA_P2H64(user_obj->ratelimit));
				}
				add_yajl_string(g, "sample");
				axa_strbuf_reset(sb_tmp);
				axa_strbuf_append(sb_tmp, "%0.2f",
					((double)AXA_P2H64(user_obj->sample)));
				add_yajl_number_sb(g, sb_tmp);
				add_yajl_string(g, "last_count_update");
				t = AXA_P2H32(user_obj->last_cnt_update.tv_sec);
				tm_info = gmtime(&t);
				strftime(time_buf, sizeof (time_buf),
						"%Y-%m-%dT%H:%M:%SZ",
						tm_info);
				add_yajl_string(g, time_buf);
				add_yajl_string(g, "filtered");
				add_yajl_integer(g, user_obj->filtered);
				add_yajl_string(g, "missed");
				add_yajl_integer(g, user_obj->missed);
				add_yajl_string(g, "collected");
				add_yajl_integer(g, user_obj->collected);
				add_yajl_string(g, "sent");
				add_yajl_integer(g, user_obj->sent);
				add_yajl_string(g, "rlimit");
				add_yajl_integer(g, user_obj->rlimit);
				add_yajl_string(g, "congested");
				add_yajl_integer(g, user_obj->congested);
				switch (user_obj->server_type) {
					case _AXA_STATS_SRVR_TYPE_SRA:
						add_yajl_string(g,
								"ipv4_watch_cnt");
						add_yajl_integer(g,
								AXA_P2H32(user_obj->srvr.sra.watches.ipv4_cnt));
						add_yajl_string(g,
								"ipv6_watch_cnt");
						add_yajl_integer(g,
								AXA_P2H32(user_obj->srvr.sra.watches.ipv6_cnt));
						add_yajl_string(g,
								"dns_watch_cnt");
						add_yajl_integer(g,
								AXA_P2H32(user_obj->srvr.sra.watches.dns_cnt));
						add_yajl_string(g,
								"ch_watch_cnt");
						add_yajl_integer(g,
								AXA_P2H32(user_obj->srvr.sra.watches.ch_cnt));
						add_yajl_string(g,
								"err_watch_cnt");
						add_yajl_integer(g,
								AXA_P2H32(user_obj->srvr.sra.watches.err_cnt));

						add_yajl_string(g, "channels");
						add_yajl_array(g);
						for (int j = 0; j < 256; j++) {
							if (axa_get_bitwords(user_obj->srvr.sra.ch_mask.m, j)) {
								axa_strbuf_reset(sb_tmp);
								axa_strbuf_append(sb_tmp, "ch%d", (j));
								add_yajl_string(g, (const char*)sb_tmp->data);
							}
						}
						close_yajl_array(g);
						break;
					case _AXA_STATS_SRVR_TYPE_RAD:
						add_yajl_string(g, "anomaly_count_in_flight");
						add_yajl_integer(g,
							AXA_P2H32(user_obj->srvr.rad.an_obj_cnt));
						add_yajl_string(g, "anomaly_count_total");
						add_yajl_integer(g,
							AXA_P2H32(user_obj->srvr.rad.an_obj_cnt_total));
						an_objs_cnt = user_obj->srvr.rad.an_obj_cnt;
						q = (uint8_t *)&body->stats_rsp +
							sizeof (_axa_p_stats_rsp_t) +
							body->stats_rsp.sys_objs_cnt *
							sizeof (_axa_p_stats_sys_t) +
							sizeof (_axa_p_stats_user_t);
						if (an_objs_cnt > 0) {
							have_an_objs = true;
							add_yajl_string(g,
								"anomalies");
							add_yajl_array(g);
							_axa_p_stats_user_rad_an_t *an_obj = (_axa_p_stats_user_rad_an_t *)q;
							for ( ; an_objs_cnt; an_objs_cnt--, an_obj++) {
								add_yajl_string(g, "an_obj");
								add_yajl_map(g);
								add_yajl_string(g, "name");
								add_yajl_string(g,
									an_obj->name);
								add_yajl_string(g, "options");
								add_yajl_string(g,
									an_obj->opt);
								add_yajl_string(g,
									"ru_original");
								ru = AXA_P2H32(an_obj->ru_original);
								if (ru == INT_MAX)
									add_yajl_string(g,
										"unlimited");
								else
									add_yajl_integer(g,
										AXA_P2H32(an_obj->ru_original));
								add_yajl_string(g,
									"ru_current");
								ru = AXA_P2H32(an_obj->ru_current);
								if (ru == INT_MAX)
									add_yajl_string(g,
										"unlimited");
								else
									add_yajl_integer(g,
										AXA_P2H32(an_obj->ru_current));
								add_yajl_string(g, "ru_cost");
								add_yajl_integer(g,
									AXA_P2H32(an_obj->ru_cost));
								add_yajl_string(g,
									"channels");
								add_yajl_array(g);
								for (int j = 0; j < 256; j++) {
									if (axa_get_bitwords(an_obj->ch_mask.m, j)) {
										axa_strbuf_reset(sb_tmp);
										axa_strbuf_append(sb_tmp, "ch%d", (j));
										add_yajl_string(g, (const char*)sb_tmp->data);
									}
								}
								close_yajl_array(g);
								close_yajl_map(g);
							}
							close_yajl_array(g);
						}
						break;
					default:
						res = AXA_JSON_RES_FAILURE;
						goto err;
				} /* switch (user_obj->server_type) */
				close_yajl_map(g);
			} /* for (; user_objs_cnt; user_objs_cnt--, ... */
			close_yajl_array(g);
		} /* if (user_objs_cnt > 0) */
		break;
	case _AXA_P_OP_KILL_REQ:
	case _AXA_P_OP_KILL_RSP:
		add_yajl_string(g, "mode");
		add_yajl_integer(g, body->kill.mode);
		add_yajl_string(g, "user");
		add_yajl_string(g, body->kill.user.name);
		add_yajl_string(g, "sn");
		add_yajl_integer(g, AXA_P2H32(body->kill.sn));
		add_yajl_string(g, "result");
		add_yajl_integer(g, body->kill.result);
		break;
	case AXA_P_OP_PAUSE:
	case AXA_P_OP_GO:
	case AXA_P_OP_WGET:
	case AXA_P_OP_AGET:
	case AXA_P_OP_STOP:
	case AXA_P_OP_ALL_STOP:
	case AXA_P_OP_CGET:
	case AXA_P_OP_ACCT:
	case AXA_P_OP_RADU:
		break;
	case AXA_P_OP_MGMT_GETRSP:
	case AXA_P_OP_MGMT_GET:
		add_yajl_string(g, "mgmt is deprecated; please upgrade and use \"stats\"");
		break;
	} /* switch */

	close_yajl_map(g);

	yajl_gen_reset(g, "");
	yajl_gen_free(g);

	*out = sb->data;
	free(sb);
	axa_strbuf_destroy(&sb_tmp);

	return (AXA_JSON_RES_SUCCESS);

err:
	if (g != NULL)
		yajl_gen_free(g);
	axa_strbuf_destroy(&sb);
	axa_strbuf_destroy(&sb_tmp);
	return (res);
}

#else /* HAVE_YAJL */
axa_json_res_t
axa_body_to_json(__attribute__((__unused__)) axa_emsg_t *emsg,
		 __attribute__((__unused__)) nmsg_input_t nmsg_input,
		 __attribute__((__unused__)) axa_p_hdr_t *hdr,
		 __attribute__((__unused__)) axa_p_body_t *body,
		 __attribute__((__unused__)) size_t body_len,
		 __attribute__((__unused__)) char **out)
{
	return (AXA_JSON_RES_NOTIMPL);
}
#endif /* HAVE_YAJL */
