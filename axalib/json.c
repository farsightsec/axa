/*
 * Advanced Exchange Access (AXA) protocol definitions
 *
 * This file is used outside the AXA programs.
 *
 *  Copyright (c) 2014-2018,2021 by Farsight Security, Inc.
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

#ifdef HAVE_JSON_C

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
#include <axa/wire.h>
#include <axa/json_c_shortcuts.h>
#include <string.h>
#include <libmy/b64_encode.h>
#include <json-c/json_object.h>
#include <json-c/json_tokener.h>


static void
add_anom(struct json_object *g, axa_p_anom_t anom, bool print_parms)
{
	json_c_add_string(g, "an", anom.an.c);

	if (print_parms)
		json_c_add_string(g, "parms", anom.parms);
}

static void
add_channel(struct json_object *g, axa_p_ch_t ch) {
	if (ch == AXA_P2H_CH(AXA_OP_CH_ALL)) {
		json_c_add_string(g, "channel", AXA_OP_CH_ALLSTR);
	} else {
		char tmps[sizeof(AXA_OP_CH_PREFIX) + 16] = {0};
		snprintf(tmps, sizeof(tmps), "%s%d", AXA_OP_CH_PREFIX, ch);
		json_c_add_string(g, "channel", tmps);
	}
}

static axa_json_res_t
add_rlimit_count(struct json_object *g, const char *fieldname, axa_cnt_t count)
{
	if (AXA_P2H64(count) == AXA_RLIMIT_OFF)
		json_c_add_string(g, fieldname, "off");
	else if (AXA_P2H64(count) == AXA_RLIMIT_NA)
		json_c_add_null(g, fieldname);
	else
		json_c_add_number(g, fieldname, AXA_P2H64(count));

	return (AXA_JSON_RES_SUCCESS);
}

static void
add_watch(struct json_object *g, axa_p_watch_t *watch, size_t watch_len)
{
	char buf[AXA_P_STRLEN];
	const char *wtype = NULL;

	switch ((axa_p_watch_type_t)watch->type) {
	case AXA_P_WATCH_IPV4:
		wtype = "ipv4";
		break;
	case AXA_P_WATCH_IPV6:
		wtype = "ipv6";
		break;
	case AXA_P_WATCH_DNS:
		wtype = "dns";
		break;
	case AXA_P_WATCH_CH:
		wtype = "channel";
		break;
	case AXA_P_WATCH_ERRORS:
		wtype = "errors";
		break;
	} /* switch */

	if (wtype != NULL)
		json_c_add_string(g, "watch_type", wtype);

	axa_watch_to_str(buf, sizeof(buf), watch, watch_len);
	json_c_add_string(g, "watch", buf);
}

static axa_json_res_t
add_whit(axa_emsg_t *emsg, struct json_object *g, nmsg_input_t nmsg_input, axa_p_whit_t *whit, size_t whit_len)
{
	add_channel(g, whit->hdr.ch);

	switch (whit->hdr.type) {
	case AXA_P_WHIT_NMSG: {
		nmsg_message_t msg;
		axa_w2n_res_t wres;
		nmsg_res nres;
		const char *vname, *mname;
		char *nmsg_json = NULL;
		struct tm tm;
		time_t t;
		char when[32], tbuf[64];

		if (whit_len < sizeof(axa_p_whit_nmsg_t)) {
			axa_pemsg(emsg, "whit_len %zu < %zu", whit_len, sizeof(axa_p_whit_nmsg_t));
			return (AXA_JSON_RES_FAILURE);
		}

		wres = axa_whit2nmsg(emsg, nmsg_input, &msg, whit, whit_len);
		if (wres != AXA_W2N_RES_SUCCESS) {
			return (AXA_JSON_RES_FAILURE);
		}

		if(AXA_P2H_IDX(whit->nmsg.hdr.field_idx) < AXA_NMSG_IDX_RSVD) {
			const char *field_name;
			nres = nmsg_message_get_field_name(msg, whit->nmsg.hdr.field_idx, &field_name);
			if (nres == nmsg_res_success)
				json_c_add_string(g, "field", field_name);
			else
				json_c_add_number(g, "field_idx", AXA_P2H_IDX(whit->nmsg.hdr.field_idx));
		}

		if (AXA_P2H_IDX(whit->nmsg.hdr.val_idx) < AXA_NMSG_IDX_RSVD)
			json_c_add_number(g, "val_idx", AXA_P2H_IDX(whit->nmsg.hdr.val_idx));

		vname = nmsg_msgmod_vid_to_vname(AXA_P2H_IDX(whit->nmsg.hdr.vid));
		if (vname != NULL)
			json_c_add_string(g, "vname", vname);
		else
			json_c_add_number(g, "vid", AXA_P2H_IDX(whit->nmsg.hdr.vid));

		mname = nmsg_msgmod_msgtype_to_mname(
				AXA_P2H16(whit->nmsg.hdr.vid), AXA_P2H16(whit->nmsg.hdr.type));
		if (mname != NULL)
			json_c_add_string(g, "mname", mname);
		else
			json_c_add_number(g, "msgtype", AXA_P2H_IDX(whit->nmsg.hdr.type));

		t = AXA_P2H32(whit->nmsg.hdr.ts.tv_sec);
		gmtime_r(&t, &tm);
		strftime(when, sizeof(when), "%Y-%m-%d %T", &tm);

		snprintf(tbuf, sizeof(tbuf), "%s.%09u", when, AXA_P2H32(whit->nmsg.hdr.ts.tv_nsec));
		json_c_add_string(g, "time", tbuf);

		nres = nmsg_message_to_json(msg, &nmsg_json);
		if (nres == nmsg_res_success) {
			struct json_object *node = json_tokener_parse(nmsg_json);

			if (node != NULL) {
				int status = json_object_object_add(g, "nmsg", node);
				AXA_ASSERT(status == 0);
			}

			free(nmsg_json);
		}

		nmsg_message_destroy(&msg);

		return (AXA_JSON_RES_SUCCESS);
	}
	case AXA_P_WHIT_IP: {
		struct nmsg_ipdg dg;
		nmsg_res res;
		struct tm tm;
		time_t t;
		char when[32], tbuf[64];

		if (whit_len < sizeof(axa_p_whit_ip_t)) {
			axa_pemsg(emsg, "whit_len %zu < %zu", whit_len, sizeof(axa_p_whit_ip_t));
			return (AXA_JSON_RES_FAILURE);
		}

		t = AXA_P2H32(whit->ip.hdr.tv.tv_sec);
		gmtime_r(&t, &tm);
		strftime(when, sizeof(when), "%Y-%m-%d %T", &tm);
		snprintf(tbuf, sizeof(tbuf), "%s.%06u", when, AXA_P2H32(whit->ip.hdr.tv.tv_usec));
		json_c_add_string(g, "time", tbuf);

		res = nmsg_ipdg_parse_pcap_raw(&dg, DLT_RAW, whit->ip.b,
			whit_len - offsetof(axa_p_whit_ip_t, b));
		if (res != nmsg_res_success || dg.len_network == 0) {
			json_c_add_bool(g, "parse_error", true);
			return (AXA_JSON_RES_SUCCESS);
		}

		switch(dg.proto_network) {
		case AF_INET: {
			struct ip *ip_hdr;
			char addr_str[INET_ADDRSTRLEN];

			json_c_add_string(g, "af", "IPv4");

			if (dg.network != NULL && dg.len_network >= sizeof(ip_hdr)) {
				ip_hdr = (void*)dg.network;

				json_c_add_string(g, "src",
					inet_ntop(AF_INET, &ip_hdr->ip_src, addr_str, sizeof(addr_str)));
				json_c_add_string(g, "dst",
					inet_ntop(AF_INET, &ip_hdr->ip_dst, addr_str, sizeof(addr_str)));
				json_c_add_number(g, "ttl", ip_hdr->ip_ttl);
			}
			break;
		}
		case AF_INET6: {
			struct ip6_hdr *ip6_hdr;
			char addr_str[INET6_ADDRSTRLEN];

			json_c_add_string(g, "af", "IPv6");

			if (dg.network != NULL && dg.len_network >= sizeof(ip6_hdr)) {
				ip6_hdr = (void*)dg.network;

				json_c_add_string(g, "src",
					inet_ntop(AF_INET6, &ip6_hdr->ip6_src, addr_str, sizeof(addr_str)));
				json_c_add_string(g, "dst",
					inet_ntop(AF_INET6, &ip6_hdr->ip6_dst, addr_str, sizeof(addr_str)));
				json_c_add_number(g, "ttl", ip6_hdr->ip6_hlim);

			}
			break;
		}
		default:
			json_c_add_number(g, "af", dg.proto_network);
			return (AXA_JSON_RES_SUCCESS);
		} /* switch */

		switch(dg.proto_transport) {
		case IPPROTO_ICMP:
			json_c_add_string(g, "proto", "ICMP");
			break;
		case IPPROTO_ICMPV6:
			json_c_add_string(g, "proto", "ICMPv6");
			break;
		case IPPROTO_TCP:
			json_c_add_string(g, "proto", "TCP");
			if (dg.transport != NULL && dg.len_transport >= sizeof(struct tcphdr)) {
				struct tcphdr *tcp_hdr = (void*)dg.transport;
				struct json_object *jflags;
				int status;

				jflags = json_object_new_array();
				AXA_ASSERT(jflags != NULL);

				json_c_add_number(g, "src_port", ntohs(tcp_hdr->th_sport));
				json_c_add_number(g, "dst_port", ntohs(tcp_hdr->th_dport));

				if ((tcp_hdr->th_flags & TH_FIN) != 0)
					json_c_add_string_to_array(jflags, "FIN");
				if ((tcp_hdr->th_flags & TH_SYN) != 0)
					json_c_add_string_to_array(jflags, "SYN");
				if ((tcp_hdr->th_flags & TH_ACK) != 0)
					json_c_add_string_to_array(jflags, "ACK");
				if ((tcp_hdr->th_flags & TH_RST) != 0)
					json_c_add_string_to_array(jflags, "RST");

				status = json_object_object_add(g, "flags", jflags);
				AXA_ASSERT(status == 0);
			}
			break;
		case IPPROTO_UDP:
			json_c_add_string(g, "proto", "UDP");
			if (dg.transport != NULL && dg.len_transport >= sizeof(struct udphdr)) {
				struct udphdr *udp_hdr = (void*)dg.transport;

				json_c_add_number(g, "src_port", ntohs(udp_hdr->uh_sport));
				json_c_add_number(g, "dst_port", ntohs(udp_hdr->uh_dport));
			}
			break;
		default:
			json_c_add_number(g, "proto", dg.proto_transport);
			break;
		} /* switch */

		if (dg.payload != NULL) {
			base64_encodestate b64;
			char *b64_str;
			size_t b64_str_len;

			base64_init_encodestate(&b64);
			b64_str = alloca(2 * dg.len_payload + 1);
			AXA_ASSERT(b64_str != NULL);

			b64_str_len = base64_encode_block((void*)dg.payload, dg.len_payload, b64_str, &b64);
			b64_str_len += base64_encode_blockend(b64_str + b64_str_len, &b64);

			json_c_add_string_len(g, "payload", b64_str, b64_str_len);
		}

		return (AXA_JSON_RES_SUCCESS);
	}
	default:
		axa_pemsg(emsg, "unknown whit hdr type: %d", whit->hdr.type);
		return (AXA_JSON_RES_FAILURE);
	}
}

static struct json_object *
get_user_obj(axa_p_body_t *body, _axa_p_stats_user_t *user_obj)
{
	struct json_object *jobj, *jchannels;
	struct tm *tm_info;
	uint8_t *q;
	char addr_str[INET6_ADDRSTRLEN], time_buf[30], tmpb[64] = {0};
	const char *iotype_str = NULL;
	_axa_p_stats_user_rad_an_t *an_obj;
	axa_ch_mask_t mask;
	runits_t ru;
	time_t t;
	double tmpd;
	int status;
	uint16_t an_objs_cnt;

	jobj = json_object_new_object();
	AXA_ASSERT(jobj != NULL);

	if (user_obj->server_type == _AXA_STATS_SRVR_TYPE_SRA)
		json_c_add_string(jobj, "server_type", "sra");
	else if (user_obj->server_type ==_AXA_STATS_SRVR_TYPE_RAD)
		json_c_add_string(jobj, "server_type", "rad");
	else
		json_c_add_string(jobj, "server_type", "unkwn");

	json_c_add_string(jobj, "user", user_obj->user.name);
	json_c_add_bool(jobj, "is_admin", (user_obj->is_admin == 1));

	switch (user_obj->io_type) {
	case AXA_IO_TYPE_UNIX:
		iotype_str = AXA_IO_TYPE_UNIX_STR;
		break;
	case AXA_IO_TYPE_TCP:
		iotype_str = AXA_IO_TYPE_TCP_STR;
		break;
	case AXA_IO_TYPE_APIKEY:
		iotype_str = AXA_IO_TYPE_APIKEY_STR;
		break;
	case AXA_IO_TYPE_UNKN:
	default:
		iotype_str = "unknown";
		break;
	}
	json_c_add_string(jobj, "io_type", iotype_str);

	if (user_obj->addr_type == AXA_AF_INET)
		inet_ntop(AF_INET, &user_obj->ip.ipv4, addr_str, sizeof(addr_str));
	else if (user_obj->addr_type == AXA_AF_INET6)
		inet_ntop(AF_INET6, &user_obj->ip.ipv6, addr_str, sizeof(addr_str));
	else
		strlcpy(addr_str, "unknown", sizeof(addr_str));

	json_c_add_string(jobj, "address", addr_str);
	json_c_add_number(jobj, "sn", user_obj->sn);

	t = AXA_P2H32(user_obj->connected_since.tv_sec);
	tm_info = gmtime(&t);
	strftime(time_buf, sizeof(time_buf), "%Y-%m-%dT%H:%M:%SZ", tm_info);
	json_c_add_string(jobj, "connected_since", time_buf);

	if (AXA_P2H64(user_obj->ratelimit) == AXA_RLIMIT_OFF)
		json_c_add_number(jobj, "ratelimit", 0);
	else
		json_c_add_number(jobj, "ratelimit", AXA_P2H64(user_obj->ratelimit));

	tmpd = AXA_P2H64(user_obj->sample) * 1.0;
	snprintf(tmpb, sizeof(tmpb), "%0.2f", tmpd);
	json_c_add_double_s(jobj, "sample", tmpd, tmpb);

	t = AXA_P2H32(user_obj->last_cnt_update.tv_sec);
	tm_info = gmtime(&t);
	strftime(time_buf, sizeof(time_buf), "%Y-%m-%dT%H:%M:%SZ", tm_info);
	json_c_add_string(jobj, "last_count_update", time_buf);

	json_c_add_number(jobj, "filtered", user_obj->filtered);
	json_c_add_number(jobj, "missed", user_obj->missed);
	json_c_add_number(jobj, "collected", user_obj->collected);
	json_c_add_number(jobj, "sent", user_obj->sent);
	json_c_add_number(jobj, "rlimit", user_obj->rlimit);
	json_c_add_number(jobj, "congested", user_obj->congested);

	switch (user_obj->server_type) {
	case _AXA_STATS_SRVR_TYPE_SRA:
		json_c_add_number(jobj, "ipv4_watch_cnt", AXA_P2H32(user_obj->srvr.sra.watches.ipv4_cnt));
		json_c_add_number(jobj, "ipv6_watch_cnt", AXA_P2H32(user_obj->srvr.sra.watches.ipv6_cnt));
		json_c_add_number(jobj, "dns_watch_cnt", AXA_P2H32(user_obj->srvr.sra.watches.dns_cnt));
		json_c_add_number(jobj, "ch_watch_cnt", AXA_P2H32(user_obj->srvr.sra.watches.ch_cnt));
		json_c_add_number(jobj, "err_watch_cnt", AXA_P2H32(user_obj->srvr.sra.watches.err_cnt));

		jchannels = json_object_new_array();
		AXA_ASSERT(jchannels != NULL);

		mask = user_obj->srvr.sra.ch_mask;
		for (int j = 0; j <= AXA_NMSG_CH_MAX; j++) {
			if (axa_get_bitwords(mask.m, j)) {
				snprintf(tmpb, sizeof(tmpb), "ch%d", j);
				json_c_add_string_to_array(jchannels, tmpb);
			}
		}
		status = json_object_object_add(jobj, "channels", jchannels);
		AXA_ASSERT(status == 0);
		break;
	case _AXA_STATS_SRVR_TYPE_RAD:
		json_c_add_number(jobj, "anomaly_count_in_flight", AXA_P2H32(user_obj->srvr.rad.an_obj_cnt));
		json_c_add_number(jobj, "anomaly_count_total", AXA_P2H32(user_obj->srvr.rad.an_obj_cnt_total));
		an_objs_cnt = user_obj->srvr.rad.an_obj_cnt;
		q = (uint8_t *)&body->stats_rsp + sizeof(_axa_p_stats_rsp_t) +
			body->stats_rsp.sys_objs_cnt * sizeof(_axa_p_stats_sys_t) + sizeof(_axa_p_stats_user_t);
		if (an_objs_cnt > 0) {
			struct json_object *janoms;

			janoms = json_object_new_array();
			AXA_ASSERT(janoms != NULL);

			an_obj = (_axa_p_stats_user_rad_an_t *)q;
			for ( ; an_objs_cnt; an_objs_cnt--, an_obj++) {
				struct json_object *janom, *jchan;

				janom = json_object_new_object();
				AXA_ASSERT(janom != NULL);

				json_c_add_string(janom, "name", an_obj->name);
				json_c_add_string(janom, "options", an_obj->opt);
				ru = AXA_P2H32(an_obj->ru_original);
				if (ru == INT_MAX)
					json_c_add_string(janom, "ru_original", "unlimited");
				else
					json_c_add_number(janom, "ru_original", AXA_P2H32(an_obj->ru_original));
				ru = AXA_P2H32(an_obj->ru_current);
				if (ru == INT_MAX)
					json_c_add_string(janom, "ru_current", "unlimited");
				else
					json_c_add_number(janom, "ru_current", AXA_P2H32(an_obj->ru_current));
				json_c_add_number(janom, "ru_cost", AXA_P2H32(an_obj->ru_cost));

				jchan = json_object_new_array();
				AXA_ASSERT(jchan != NULL);

				mask = an_obj->ch_mask;
				for (int j = 0; j <= AXA_NMSG_CH_MAX; j++) {
					if (axa_get_bitwords(mask.m, j)) {
						char chbuf[16] = {0};
						snprintf(chbuf, sizeof(chbuf), "ch%d", j);
						json_c_add_string_to_array(jchan, chbuf);
					}
				}
				status = json_object_object_add(janom, "channels", jchan);
				AXA_ASSERT(status == 0);
				json_c_add_string_to_array(janoms, "an_obj");
				json_c_add_to_array(janoms, janom);
			}
			status = json_object_object_add(jobj, "anomalies", janoms);
			AXA_ASSERT(status == 0);
		}
		break;
	default:
		json_object_put(jobj);
		jobj = NULL;
	} // switch (user_obj->server_type)

	return jobj;
}

axa_json_res_t
axa_body_to_json(axa_emsg_t *emsg, nmsg_input_t nmsg_input, axa_p_hdr_t *hdr, axa_p_body_t *body, size_t body_len, char **out)
{
	axa_json_res_t res;
	struct json_object *g = NULL;
	char op_str[AXA_P_OP_STRLEN];
	axa_p_direction_t dir;
	uint8_t *p;
	uint16_t user_objs_cnt;
	_axa_p_stats_sys_t *sys;
	_axa_p_stats_user_t *user_obj;
	axa_ch_mask_t mask;

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

	if (!axa_ck_hdr(emsg, hdr, "json", dir))
		return (AXA_JSON_RES_FAILURE);

	if (AXA_P2H32(hdr->len) - sizeof(axa_p_hdr_t) != body_len) {
		axa_pemsg(emsg, "body length mismatch %zu != %zu",
			AXA_P2H32(hdr->len) - sizeof(axa_p_hdr_t), body_len);
		return (AXA_JSON_RES_FAILURE);
	}

	if (!axa_ck_body(emsg, hdr->op, body, body_len))
		return (AXA_JSON_RES_FAILURE);

	g = json_object_new_object();
	AXA_ASSERT(g != NULL);

	if (AXA_P2H16(hdr->tag) == AXA_TAG_NONE)
		json_c_add_string(g, "tag", "*");
	else
		json_c_add_number(g, "tag", AXA_P2H16(hdr->tag));

	axa_op_to_str(op_str, sizeof(op_str), hdr->op);
	json_c_add_string(g, "op", op_str);

	switch ((axa_p_op_t)hdr->op) {
	case AXA_P_OP_NOP:
		break;
	case AXA_P_OP_HELLO:
		json_c_add_number(g, "id", AXA_P2H64(body->hello.id));
		json_c_add_number(g, "pvers_min", body->hello.pvers_min);
		json_c_add_number(g, "pvers_max", body->hello.pvers_max);
		json_c_add_string(g, "str", body->hello.str);
		break;
	case AXA_P_OP_OK:
	case AXA_P_OP_ERROR:
		axa_op_to_str(op_str, sizeof(op_str), body->result.orig_op);
		json_c_add_string(g, "orig_op", op_str);
		json_c_add_string(g, "str", body->result.str);
		break;
	case AXA_P_OP_MISSED:
		json_c_add_number(g, "missed", AXA_P2H64(body->missed.missed));
		json_c_add_number(g, "dropped", AXA_P2H64(body->missed.dropped));
		json_c_add_number(g, "rlimit", AXA_P2H64(body->missed.rlimit));
		json_c_add_number(g, "filtered", AXA_P2H64(body->missed.filtered));
		json_c_add_number(g, "last_report", AXA_P2H32(body->missed.last_report));
		break;
	case AXA_P_OP_MISSED_RAD:
		json_c_add_number(g, "sra_missed", AXA_P2H64(body->missed_rad.sra_missed));
		json_c_add_number(g, "sra_dropped", AXA_P2H64(body->missed_rad.sra_dropped));
		json_c_add_number(g, "sra_rlimit", AXA_P2H64(body->missed_rad.sra_rlimit));
		json_c_add_number(g, "sra_filtered", AXA_P2H64(body->missed_rad.sra_filtered));
		json_c_add_number(g, "dropped", AXA_P2H64(body->missed_rad.dropped));
		json_c_add_number(g, "rlimit", AXA_P2H64(body->missed_rad.rlimit));
		json_c_add_number(g, "filtered", AXA_P2H64(body->missed_rad.filtered));
		json_c_add_number(g, "last_report", AXA_P2H32(body->missed_rad.last_report));
		break;
	case AXA_P_OP_WHIT:
		res = add_whit(emsg, g, nmsg_input, &(body->whit), body_len);
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
		add_channel(g, body->channel.ch);
		json_c_add_bool(g, "on", (body->channel.on != 0));
		break;
	case AXA_P_OP_WLIST:
		json_c_add_number(g, "cur_tag", AXA_P2H16(body->wlist.cur_tag));
		add_watch(g, &(body->wlist.w), body_len - offsetof(axa_p_wlist_t, w));
		break;
	case AXA_P_OP_AHIT:
		json_c_add_string(g, "an", body->ahit.an.c);

		res = add_whit(emsg, g, nmsg_input, &(body->ahit.whit), body_len - offsetof(axa_p_ahit_t, whit));
		if (res != AXA_JSON_RES_SUCCESS)
			goto err;
		break;
	case AXA_P_OP_ALIST: {
		bool print_parms;
		json_c_add_number(g, "cur_tag", AXA_P2H16(body->alist.cur_tag));
		print_parms = body_len > offsetof(axa_p_alist_t, anom) + offsetof(axa_p_anom_t, parms) &&
			body->alist.anom.parms[0] != '\0';
		add_anom(g, body->alist.anom, print_parms);
		break;
	}
	case AXA_P_OP_CLIST:
		add_channel(g, body->clist.ch);
		json_c_add_bool(g, "on", (body->clist.on != 0));
		json_c_add_string(g, "spec", body->clist.spec.c);
		break;
	case AXA_P_OP_USER:
		json_c_add_string(g, "name", body->user.name);
		break;
	case AXA_P_OP_OPT: {
		char buf[AXA_P_OP_STRLEN];

		axa_opt_to_str(buf, sizeof(buf), AXA_P2H64(body->opt.type));
		json_c_add_string(g, "type", buf);

		switch((axa_p_opt_type_t)body->opt.type) {
			case AXA_P_OPT_TRACE: {
				if (AXA_P2H64(body->opt.u.trace) != AXA_P_OPT_TRACE_REQ)
					json_c_add_number(g, "trace", AXA_P2H64(body->opt.u.trace));
				else
					json_c_add_string(g, "trace", "REQUEST TRACE VALUE");
				break;
			}
			case AXA_P_OPT_RLIMIT:
				res = add_rlimit_count(g, "max_pkts_per_sec",
					body->opt.u.rlimit.max_pkts_per_sec);
				if (res != AXA_JSON_RES_SUCCESS)
					goto err;

				json_c_add_number(g, "cur_pkts_per_sec",
					AXA_P2H64(body->opt.u.rlimit.cur_pkts_per_sec));

				res = add_rlimit_count(g, "report_secs", body->opt.u.rlimit.report_secs);
				if (res != AXA_JSON_RES_SUCCESS)
					goto err;
				break;
			case AXA_P_OPT_SAMPLE:
				if (AXA_P2H64(body->opt.u.sample) == 0)
					json_c_add_string(g, "sample", "requested");
				else {
					char sval[64] = {0};
					double samp_val = AXA_P2H64(body->opt.u.sample) / AXA_P_OPT_SAMPLE_MAX;
					snprintf(sval, sizeof(sval), "%0.6f", samp_val);
					json_c_add_double_s(g, "sample", samp_val, sval);
				}
				break;
			case AXA_P_OPT_SNDBUF:
				json_c_add_number(g, "bufsize", AXA_P2H64(body->opt.u.bufsize));
				break;
		} /* switch */
		break;
	}
	case AXA_P_OP_JOIN:
		json_c_add_number(g, "id", AXA_P2H64(body->join.id));
		break;
	case _AXA_P_OP_STATS_REQ:
		const char *type_str;

		if (body->stats_req.version != _AXA_STATS_VERSION_ONE) {
			res = AXA_JSON_RES_FAILURE;
			goto err;
		}
		json_c_add_number(g, "version", body->stats_req.version);

		switch (body->stats_req.type) {
			case AXA_P_STATS_M_M_SUM:
				type_str = "summary";
				break;
			case AXA_P_STATS_M_M_ALL:
				type_str = "all";
				break;
			case AXA_P_STATS_M_M_SN:
				type_str = "serial number";
				break;
			case AXA_P_STATS_M_M_U:
				type_str = "user name";
				break;
			default:
				type_str = "unknown";
		}
		json_c_add_string(g, "type", type_str);

		if (body->stats_req.type == AXA_P_STATS_M_M_SN)
			json_c_add_number(g, "serial number", body->stats_req.sn);
		if (body->stats_req.type == AXA_P_STATS_M_M_U)
			json_c_add_string(g, "user name", body->stats_req.user.name);

		break;
	case _AXA_P_OP_STATS_RSP:
		if (body->stats_rsp.version != _AXA_STATS_VERSION_ONE) {
			res = AXA_JSON_RES_FAILURE;
			goto err;
		}
		json_c_add_number(g, "version", body->stats_rsp.version);

		if (body->stats_rsp.sys_objs_cnt > 1) {
			res = AXA_JSON_RES_FAILURE;
			goto err;
		}

		switch (body->stats_rsp.result) {
			case AXA_P_STATS_R_SUCCESS:
				json_c_add_string(g, "result", "success");
				break;
			case AXA_P_STATS_R_FAIL_NF:
				json_c_add_string(g, "result", "failed: user not found");
				break;
			case AXA_P_STATS_R_FAIL_UNK:
			default:
				json_c_add_string(g, "result", "failed: unknown reason");
				break;
		}

		if (body->stats_rsp.sys_objs_cnt == 1) {
			struct json_object *jload;
			int status;
			p = (uint8_t *)&body->stats_rsp;
			sys = (_axa_p_stats_sys_t *)(p + sizeof(_axa_p_stats_rsp_t));

			if (sys->type != _AXA_P_STATS_TYPE_SYS) {
				res = AXA_JSON_RES_FAILURE;
				goto err;
			}

			jload = json_object_new_array();
			AXA_ASSERT(jload != NULL);

			json_c_add_to_array(jload, json_object_new_uint64(AXA_P2H32(sys->load[0])));
			json_c_add_to_array(jload, json_object_new_uint64(AXA_P2H32(sys->load[1])));
			json_c_add_to_array(jload, json_object_new_uint64(AXA_P2H32(sys->load[2])));
			status = json_object_object_add(g, "load", jload);
			AXA_ASSERT(status == 0);

			json_c_add_number(g, "cpu_usage", AXA_P2H32(sys->cpu_usage));
			json_c_add_number(g, "uptime", AXA_P2H32(sys->uptime));
			json_c_add_number(g, "starttime", AXA_P2H32(sys->starttime));
			json_c_add_number(g, "vmsize", AXA_P2H64(sys->vmsize));
			json_c_add_number(g, "vmrss", AXA_P2H64(sys->vmrss));
			json_c_add_number(g, "thread_cnt", AXA_P2H32(sys->thread_cnt));
			json_c_add_number(g, "user_cnt", AXA_P2H32(sys->user_cnt));

			switch (sys->server_type) {
				case _AXA_STATS_SRVR_TYPE_SRA:
					struct json_object *jchannels;
					json_c_add_string(g, "server_type", "sra");
					json_c_add_number(g, "fd_sockets", AXA_P2H32(sys->fd_sockets));
					json_c_add_number(g, "fd_pipes", AXA_P2H32(sys->fd_pipes));
					json_c_add_number(g, "fd_anon_inodes", AXA_P2H32(sys->fd_anon_inodes));
					json_c_add_number(g, "fd_other", AXA_P2H32(sys->fd_other));
					json_c_add_number(g, "rchar", AXA_P2H64(sys->rchar));
					json_c_add_number(g, "wchar", AXA_P2H64(sys->wchar));
					json_c_add_number(g, "sra_ipv4_watch_cnt",
						AXA_P2H32(sys->srvr.sra.watches.ipv4_cnt));
					json_c_add_number(g, "sra_ipv6_watch_cnt",
						AXA_P2H32(sys->srvr.sra.watches.ipv6_cnt));
					json_c_add_number(g, "sra_dns_watch_cnt",
						AXA_P2H32(sys->srvr.sra.watches.dns_cnt));
					json_c_add_number(g, "sra_ch_watch_cnt",
						AXA_P2H32(sys->srvr.sra.watches.ch_cnt));
					json_c_add_number(g, "sra_err_watch_cnt",
						AXA_P2H32(sys->srvr.sra.watches.err_cnt));

					jchannels = json_object_new_array();
					AXA_ASSERT(jchannels != NULL);

					mask = sys->srvr.sra.ch_mask;
					for (int j = 0; j <= AXA_NMSG_CH_MAX; j++) {
						if (axa_get_bitwords(mask.m, j)) {
							char chbuf[16] = {0};
							snprintf(chbuf, sizeof(chbuf), "ch%d", j);
							json_c_add_string_to_array(jchannels, chbuf);
						}
					}
					status = json_object_object_add(g, "sra_channels", jchannels);
					AXA_ASSERT(status == 0);
					break;
				case _AXA_STATS_SRVR_TYPE_RAD:
					json_c_add_string(g, "server_type", "rad");
					json_c_add_number(g, "rad_anomaly_cnt", AXA_P2H32(sys->srvr.rad.an_cnt));
					break;
				default:
					res = AXA_JSON_RES_FAILURE;
					goto err;
			}
		}

		user_objs_cnt = body->stats_rsp.user_objs_cnt;
		p = (uint8_t *)&body->stats_rsp + sizeof(_axa_p_stats_rsp_t) +
			body->stats_rsp.sys_objs_cnt * sizeof(_axa_p_stats_sys_t);
		if (user_objs_cnt > 0) {
			struct json_object *jusers;
			jusers = json_object_new_array();
			AXA_ASSERT(jusers != NULL);

			user_obj = (_axa_p_stats_user_t *)p;
			for (; user_objs_cnt; user_objs_cnt--, user_obj++) {
				struct json_object *juser;

				juser = get_user_obj(body, user_obj);
				if (juser == NULL)
					goto err;

				json_c_add_string_to_array(jusers, "user_obj");
				json_c_add_to_array(jusers, juser);
			}

			json_object_object_add(g, "users", jusers);
		}
		break;
	case _AXA_P_OP_KILL_REQ:
	case _AXA_P_OP_KILL_RSP:
		json_c_add_number(g, "mode", body->kill.mode);
		json_c_add_string(g, "user", body->kill.user.name);
		json_c_add_number(g, "sn", AXA_P2H32(body->kill.sn));
		json_c_add_number(g, "result", body->kill.result);
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
		json_c_add_string(g, "error", "mgmt is deprecated; please upgrade and use \"stats\"");
		break;
	} /* switch */

	*out = strdup(json_object_to_json_string_ext(g, JSON_C_TO_STRING_PLAIN|JSON_C_TO_STRING_NOSLASHESCAPE));
	json_object_put(g);

	return (AXA_JSON_RES_SUCCESS);

err:
	if (g != NULL)
		json_object_put(g);
	return (res);
}

#else /* HAVE_JSON_C */
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
#endif /* HAVE_JSON_C */
