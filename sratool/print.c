/*
 * Print various SIE messages
 *
 *  Copyright (c) 2022 DomainTools LLC
 *  Copyright (c) 2014-2018,2020-2021 by Farsight Security, Inc.
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

/* extern: cmd.c */
extern EditLine *el_e;
extern axa_mode_t mode;
extern struct timeval no_reprompt;

/* extern: infile.c */
extern int in_file_cur;

/* extern: main.c */
extern axa_emsg_t emsg;
extern uint axa_debug;
extern int packet_count;
extern bool packet_counting;
extern int packet_count_total;
extern nmsg_input_t nmsg_input;

/* extern: output.c */
extern bool out_on;
extern char *out_addr;
extern pcap_t *out_pcap;
extern int output_count;
extern bool output_counting;
extern int output_count_total;
extern nmsg_output_t out_nmsg_output;

/* extern: server.c */
extern axa_client_t client;

/* private */
static uint out_bar_idx;
static struct timeval out_bar_time;
static const char *out_bar_strs[] = {
	"|\b", "/\b", "-\b", "\\\b", "|\b", "/\b", "-\b", "\\\b"
};
#define PROGRESS_MS (1000/AXA_DIM(out_bar_strs)) /* 2 revolutions/second */

static void
print_raw(const uint8_t *pkt, size_t pkt_len)
{
	char info_buf[64], *info;
	char chars_buf[18], *chars;
	size_t info_len, chars_len;
	uint pay_pos;
	u_char c;

	info = info_buf;
	info_len = sizeof(info_buf);
	chars = chars_buf;
	chars_len = sizeof(chars_buf);
	for (pay_pos = 0; pay_pos < pkt_len; ++pay_pos) {
		if (info_len == sizeof(info_buf)) {
			if (pay_pos > 256) {
				fputs(NMSG_LEADER2"...\n", stdout);
				break;
			}
			axa_buf_print(&info, &info_len, "%7d:", pay_pos);
		}
		c = pkt[pay_pos];
		axa_buf_print(&info, &info_len, " %02x", c);
		if (c >= '!' && c <= '~')
			axa_buf_print(&chars, &chars_len, "%c", c);
		else
			axa_buf_print(&chars, &chars_len, ".");
		if (chars_len == sizeof(chars_buf) - 8) {
			axa_buf_print(&info, &info_len, " ");
			axa_buf_print(&chars, &chars_len, " ");
		} else if (chars_len == sizeof(chars_buf) - 17) {
			printf("%55s  %s\n", info_buf, chars_buf);
			info = info_buf;
			info_len = sizeof(info_buf);
			chars = chars_buf;
			chars_len = sizeof(chars_buf);
		}
	}
	if (info_len != sizeof(info_buf))
		printf("%-57s  %s\n", info_buf, chars_buf);
}

static void
print_raw_ip(const uint8_t *pkt_data, size_t caplen, axa_p_ch_t ch)
{
	axa_socku_t dst_su, src_su;
	char dst[AXA_SU_TO_STR_LEN], src[AXA_SU_TO_STR_LEN];
	char info[80];

	clear_prompt();

	if (axa_ipdg_parse(pkt_data, caplen, ch, &dst_su, &src_su,
			    info, sizeof(info))) {
		printf(" %20s > %-20s %s\n",
		       axa_su_to_str(src, sizeof(src), '.', &src_su),
		       axa_su_to_str(dst, sizeof(dst), '.', &dst_su),
		       info);
	} else {
		printf(" %s\n", info);
	}

	if (verbose > 1)
		print_raw(pkt_data, caplen);
}

/* Create nmsg message from incoming watch hit containing a nmsg message */
axa_w2n_res_t
whit2nmsg(nmsg_message_t *msgp, axa_p_whit_t *whit, size_t whit_len)
{
	axa_w2n_res_t res;

	res = axa_whit2nmsg(&emsg, nmsg_input, msgp, whit, whit_len);
	switch (res) {
		case AXA_W2N_RES_FAIL:
			clear_prompt();
			error_msg("%s", emsg.c);
			disconnect(true);
		case AXA_W2N_RES_SUCCESS:
		case AXA_W2N_RES_FRAGMENT:
			break;
	}
	return (res);
}

static void
print_nmsg(axa_p_whit_t *whit, size_t whit_len,
	   const char *title_sep, const char *title)
{
	char tag_buf[AXA_TAG_STRLEN];
	char *disp;
	nmsg_message_t msg;
	nmsg_res res;

	if (whit2nmsg(&msg, whit, whit_len) == AXA_W2N_RES_FRAGMENT) {
		if (axa_debug != 0)
			printf("ignoring NMSG fragment from "
					AXA_OP_CH_PREFIX"%d",
					AXA_P2H_CH(whit->hdr.ch));
		return;
	}
	if (msg == NULL)
		return;

	if (verbose != 0) {
		char sep[sizeof(NMSG_LEADER) + 2] = {0};

		sep[0] = '\n';
		memcpy(&sep[1], NMSG_LEADER, sizeof(NMSG_LEADER));

		res = nmsg_message_to_pres(msg, &disp, sep);
		if (res != nmsg_res_success) {
			printf(NMSG_LEADER"<UNKNOWN NMSG %u:%u>\n",
			       nmsg_message_get_vid(msg),
			       nmsg_message_get_msgtype(msg));
			goto out;
		}
	} else {
		res = nmsg_message_to_json(msg, &disp);
		if (res != nmsg_res_success) {
			fprintf(stderr, "Error serializing nmsg data as json: %s\n",
				nmsg_res_lookup(res));
			goto out;
		}
	}

	printf("%s "AXA_OP_CH_PREFIX"%d %s%s",
		axa_tag_to_str(tag_buf, sizeof(tag_buf),
			AXA_P2H_TAG(client.io.recv_hdr.tag)),
		AXA_P2H_CH(whit->hdr.ch), title_sep, title);

	if (verbose != 0)
		printf("\n%s%s\n", NMSG_LEADER, disp);
	else
		printf(" %s\n", disp);

	free(disp);

out:
	nmsg_message_destroy(&msg);
}

void
print_whit(axa_p_whit_t *whit, size_t whit_len,
	   const char *title_sep, const char *title)
{
	struct timeval now;
	time_t ms;
	char tag_buf[AXA_TAG_STRLEN];
	bool fwded;

	/* Forward binary packets if necessary. */
	if (out_on) {
		if (out_nmsg_output != NULL) {
			fwded = out_whit_nmsg(whit, whit_len);
		} else {
			AXA_ASSERT(out_pcap != NULL);
			fwded = out_whit_pcap(whit, whit_len);
		}
		if (fwded && --output_count == 0 && output_counting) {
			clear_prompt();
			printf("output %d packets to %s finished\n",
			       output_count_total, out_addr);
			out_close(true);
		}
	}

	if (--packet_count < 0 && packet_counting) {
		clear_prompt();
		if (packet_count == -1) {
			fputs("\npacket count limit exceeded\n", stdout);
		} else if (in_file_cur == 0 && el_e != NULL) {
			gettimeofday(&now, NULL);
			ms = axa_elapsed_ms(&now, &out_bar_time);
			if (ms >= PROGRESS_MS) {
				fputs(out_bar_strs[out_bar_idx], stdout);
				fflush(stdout);
				no_reprompt = now;
				++out_bar_idx;
				out_bar_idx %= AXA_DIM(out_bar_strs);
				out_bar_time = now;
			}
		}
		return;
	}

	clear_prompt();
	switch ((axa_p_whit_enum_t)whit->hdr.type) {
	case AXA_P_WHIT_NMSG:
		print_nmsg(whit, whit_len, title_sep, title);
		return;
	case AXA_P_WHIT_IP:
		if (whit_len <= sizeof(whit->ip)) {
			error_msg("truncated IP packet");
			disconnect(true);
			return;
		}

		printf("%s%s%s "AXA_OP_CH_PREFIX"%d\n",
		       axa_tag_to_str(tag_buf, sizeof(tag_buf),
				      AXA_P2H_TAG(client.io.recv_hdr.tag)),
		       title_sep, title,
		       AXA_P2H_CH(whit->hdr.ch));
		print_raw_ip(whit->ip.b, whit_len - sizeof(whit->ip.hdr),
			     AXA_P2H_CH(whit->hdr.ch));
		return;
	}
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wunreachable-code"
	error_msg("unrecognized message type %d", whit->hdr.type);
	disconnect(true);
#pragma clang diagnostic pop
}

void
print_ahit(void)
{
	print_whit(&client.io.recv_body->ahit.whit,
		   client.io.recv_hdr.len
		   - (sizeof(client.io.recv_hdr)
		      + sizeof(client.io.recv_body->ahit)
		      - sizeof(client.io.recv_body->ahit.whit)),
		   " ", client.io.recv_body->ahit.an.c);
}

void
print_channel(void)
{
	const axa_p_clist_t *clist;
	axa_p_ch_buf_t buf;

	clear_prompt();
	clist = &client.io.recv_body->clist;
	snprintf(buf.c, sizeof(buf),
		 AXA_OP_CH_PREFIX"%d", AXA_P2H_CH(clist->ch));
	printf(" %8s %3s %s\n",
	       buf.c, clist->on != 0 ? "on" : "off", clist->spec.c);
}

void
wlist_alist(void)
{
	axa_tag_t list_tag;
	char hdr_tag_buf[AXA_TAG_STRLEN];
	char list_tag_buf[AXA_TAG_STRLEN];
	char buf[AXA_P_STRLEN];

	if (client.io.recv_hdr.op == AXA_P_OP_WLIST)
		list_tag = client.io.recv_body->wlist.cur_tag;
	else
		list_tag = client.io.recv_body->alist.cur_tag;
	axa_tag_to_str(list_tag_buf, sizeof(list_tag_buf),
		       AXA_P2H_TAG(list_tag));

	clear_prompt();
	if (client.io.recv_hdr.tag != AXA_P2H_TAG(AXA_TAG_NONE)
	    && client.io.recv_hdr.tag != list_tag)
		printf("     nearest %s to %s is %s\n",
		       mode == RAD ? "anomaly" : "watch",
		       axa_tag_to_str(hdr_tag_buf, sizeof(hdr_tag_buf),
				      client.io.recv_hdr.tag),
		       list_tag_buf);

	printf("%7s %s\n",
	       list_tag_buf, axa_p_to_str(buf, sizeof(buf), false,
					  &client.io.recv_hdr,
					  client.io.recv_body));
}

void
count_print(bool always)
{
	if (always && !packet_counting)
		printf("    packet printing not limited by count\n"
				"        %d packets recently printed\n",
				0 - packet_count);
	else if (packet_count < 0)
		printf("    packet printing stopped by count %d packets ago\n",
				0 - packet_count);
	else
		printf("    %d packets remaining to print of %d total\n",
				packet_count, packet_count_total);

	if (!out_on)
		return;
	if (!output_counting)
		printf("    packet output or forwarding not limited by count\n"
				"        %d packets recently output\n",
				0 - output_count);
	else if (output_count < 0)
		printf("    packet output or forwarding stopped by count"
				" %d packets ago\n",
				0 - output_count);
	else
		printf("    %d packets remaining to output or forward of"
				" %d total\n",
				output_count, output_count_total);
}

static void
print_stats_sys(_axa_p_stats_sys_t *sys)
{
	int j, ch_cnt;
	struct timeval tv;
	const char *server_type;
	uint32_t user_cnt;
	axa_ch_mask_t mask;

	if (sys->type != _AXA_P_STATS_TYPE_SYS) {
		printf("expected system/server stats, got type \"%d\"\n",
				sys->type);
		return;
	}

	/* UINT32_MAX or UINT64_MAX == server error in gathering stat */
	if (sys->uptime == UINT32_MAX) {
		printf("    server uptime   : unavailable\n");
	}
	else {
		gettimeofday(&tv, NULL);
		tv.tv_sec -= AXA_P2H32(sys->uptime);
		printf("    server uptime   : %s\n", convert_timeval(&tv));
	}
	if (sys->load[0] == UINT32_MAX && sys->load[1] == UINT32_MAX &&
			sys->load[2] == UINT32_MAX) {
		printf("    server load     : unavailable\n");
	}
	else {
		printf("    server load     : %.2f %.2f %.2f\n",
				AXA_P2H32(sys->load[0]) * .0001,
				AXA_P2H32(sys->load[1]) * .0001,
				AXA_P2H32(sys->load[2]) * .0001);
	}

	server_type = sys->server_type == _AXA_STATS_SRVR_TYPE_SRA
		? "sra" : "rad";
	printf("    %s sys\n", server_type);
	if (sys->cpu_usage == UINT32_MAX) {
		printf("      CPU usage     : unavailable\n");
	}
	else {
		printf("      CPU usage     : %.2f%%\n",
				AXA_P2H32(sys->cpu_usage) * .0001);
	}
	if (sys->starttime == UINT32_MAX) {
		printf("      uptime        : unavailable\n");
	}
	else {
		gettimeofday(&tv, NULL);
		tv.tv_sec -= (AXA_P2H32(sys->uptime) -
				AXA_P2H32(sys->starttime));
		printf("      uptime        : %s\n", convert_timeval(&tv));
	}
	if (sys->vmsize == UINT64_MAX) {
		printf("      VM size       : unavailable\n");
	}
	else {
		printf("      VM size       : %"PRIu64"m\n",
				AXA_P2H64(sys->vmsize) / (1024 * 1024));
	}
	if (sys->vmrss == UINT64_MAX) {
		printf("      VM RSS        : unavailable\n");
	}
	else {
		printf("      VM RSS        : %"PRIu64"kb\n",
				AXA_P2H64(sys->vmrss) / 1024);
	}
	if (sys->thread_cnt == UINT32_MAX) {
		printf("      thread cnt    : unavailable\n");
	}
	else {
		printf("      thread cnt    : %"PRIu32"\n",
				AXA_P2H32(sys->thread_cnt));
	}
	if (sys->server_type != _AXA_STATS_SRVR_TYPE_RAD) {
		/* radd doesn't run as root so it can't read
		 * /proc/[pid]/fdinfo or /proc/[pid]/io
		 */
		printf("    open file descriptors\n");
		if (sys->fd_sockets == UINT32_MAX) {
			printf("      socket        : unavailable\n");
		}
		else {
			printf("      socket        : %"PRIu32"\n",
					AXA_P2H32(sys->fd_sockets));
		}
		if (sys->fd_pipes == UINT32_MAX) {
			printf("      pipe          : unavailable\n");
		}
		else {
			printf("      pipe          : %"PRIu32"\n",
					AXA_P2H32(sys->fd_pipes));
		}
		if (sys->fd_anon_inodes == UINT32_MAX) {
			printf("      anon_inode    : unavailable\n");
		}
		else {
			printf("      anon_inode    : %"PRIu32"\n",
					AXA_P2H32(sys->fd_anon_inodes));
		}
		if (sys->fd_other == UINT32_MAX) {
			printf("      other         : unavailable\n");
		}
		else {
			printf("      other         : %"PRIu32"\n",
					AXA_P2H32(sys->fd_other));
		}
		if (sys->rchar == UINT64_MAX) {
			printf("    rchar           : unavailable\n");
		}
		else {
			printf("    rchar           : %"PRIu64"\n",
					AXA_P2H64(sys->rchar));
		}
		if (sys->wchar == UINT64_MAX) {
			printf("    wchar           : unavailable\n");
		}
		else {
			printf("    wchar           : %"PRIu64"\n",
					AXA_P2H64(sys->wchar));
		}
	}
	user_cnt = AXA_P2H32(sys->user_cnt);
	printf("    users           : %d\n", user_cnt);

	if (sys->server_type == _AXA_STATS_SRVR_TYPE_SRA) {
		printf("    watches\n");
		printf("      ipv4 watches  : %u\n",
			AXA_P2H32(sys->srvr.sra.watches.ipv4_cnt));
		printf("      ipv6 watches  : %u\n",
			AXA_P2H32(sys->srvr.sra.watches.ipv6_cnt));
		printf("      dns watches   : %u\n",
			AXA_P2H32(sys->srvr.sra.watches.dns_cnt));
		printf("      ch watches    : %u\n",
			AXA_P2H32(sys->srvr.sra.watches.ch_cnt));
		printf("      err watches   : %u\n",
			AXA_P2H32(sys->srvr.sra.watches.err_cnt));
		printf("      total watches : %u\n",
			AXA_P2H32(sys->srvr.sra.watches.ipv4_cnt) +
			AXA_P2H32(sys->srvr.sra.watches.ipv6_cnt) +
			AXA_P2H32(sys->srvr.sra.watches.dns_cnt) +
			AXA_P2H32(sys->srvr.sra.watches.ch_cnt) +
			AXA_P2H32(sys->srvr.sra.watches.err_cnt));
		printf("    channels        : ");
		mask = sys->srvr.sra.ch_mask;
		for (j = ch_cnt = 0; j <= AXA_NMSG_CH_MAX; j++) {
			if (axa_get_bitwords(
				mask.m, j)) {
					printf("%u ", j);
					ch_cnt++;
			}
		}
		if (ch_cnt == 0)
			printf("none");
		printf("\n");
	}
	else /* AXA_STATS_SRVR_TYPE_RAD */ {
		printf("      anomalies     : %u\n",
			AXA_P2H32(sys->srvr.rad.an_cnt));
	}
}

static void
print_stats_user_an(_axa_p_stats_user_rad_an_t *an_obj)
{
	int j, ch_cnt;
	char ru_buf[sizeof("unlimited") + 4];
	axa_ch_mask_t mask;

	printf("        anomaly     : %s\n", an_obj->name);
	printf("        options     : %s\n", an_obj->opt);

	memset(&ru_buf, 0, sizeof (ru_buf));

	if (an_obj->ru_original == INT_MAX)
		strlcpy(ru_buf, "unlimited", sizeof(ru_buf));
	else
		snprintf(ru_buf, sizeof (ru_buf) - 1, "%d",
				an_obj->ru_original);
	printf("        RU (orig)   : %s\n", ru_buf);
	if (an_obj->ru_current == INT_MAX)
		strlcpy(ru_buf, "unlimited", sizeof(ru_buf));
	else
		snprintf(ru_buf, sizeof (ru_buf) - 1, "%d",
				an_obj->ru_current);
	printf("        RU (cur)    : %s\n", ru_buf);
	printf("        RU (cost)   : %d\n", AXA_P2H32(an_obj->ru_cost));
	printf("        channels    : ");
	mask = an_obj->ch_mask;
	for (j = ch_cnt = 0; j <= AXA_NMSG_CH_MAX; j++) {
		if (axa_get_bitwords(mask.m, j)) {
				printf("%d ", j);
				ch_cnt++;
		}
	}
	if (ch_cnt == 0)
		printf("none");
	printf("\n\n");
}

static int
print_stats_user(_axa_p_stats_user_t *user)
{
	uint8_t *p;
	time_t t;
	int j, ch_cnt, bytes_printed = 0, an_objs_cnt;
	struct timeval connected_since, last_cnt_update;
	struct tm *tm_info;
	const char *io_type;
	char time_buf[30];
	char addr_str[INET6_ADDRSTRLEN];
	axa_ch_mask_t mask;

	if (user->type != _AXA_P_STATS_TYPE_USER) {
		printf("expected user object, got type \"%d\"\n", user->type);
		return (0);
	}

	printf("\n    user            : %s (%s)\n", user->user.name,
			user->is_admin == 1 ? "admin" : "non-admin");
	switch (user->addr_type)
	{
		case AXA_AF_INET:
			inet_ntop(AF_INET, &user->ip.ipv4, addr_str,
					sizeof(addr_str));
			break;
		case AXA_AF_INET6:
			inet_ntop(AF_INET6, &user->ip.ipv6, addr_str,
					sizeof(addr_str));
			break;
		case AXA_AF_UNKNOWN:
			strlcpy(addr_str, "unknown", sizeof(addr_str));
			break;
	}
	printf("      from          : %s\n", addr_str);
	printf("      serial number : %u\n", AXA_P2H32(user->sn));
	connected_since.tv_sec = user->connected_since.tv_sec;
	connected_since.tv_usec = user->connected_since.tv_usec;
	t = AXA_P2H32(connected_since.tv_sec);
	tm_info = gmtime(&t);
		strftime(time_buf, sizeof (time_buf),
				"%Y-%m-%dT%H:%M:%SZ", tm_info);
	printf("      since         : %s (%s)\n", time_buf,
			convert_timeval(&connected_since));

	switch (user->io_type) {
		case AXA_IO_TYPE_UNIX:
			io_type = AXA_IO_TYPE_UNIX_STR;
			break;
		case AXA_IO_TYPE_TCP:
			io_type = AXA_IO_TYPE_TCP_STR;
			break;
		case AXA_IO_TYPE_APIKEY:
			io_type = AXA_IO_TYPE_APIKEY_STR;
			break;
		case AXA_IO_TYPE_UNKN:
		default:
			io_type = "unknown";
			break;
	}
	printf("      transport     : %s\n", io_type);
	switch (mode) {
		case SRA:
			printf("      channels      : ");
			mask = user->srvr.sra.ch_mask;
			for (j = ch_cnt = 0; j <= AXA_NMSG_CH_MAX; j++) {
				if (axa_get_bitwords(
					mask.m, j)) {
						printf("%d ", j);
						ch_cnt++;
				}
			}
			if (ch_cnt == 0)
				printf("none");
			printf("\n");
			printf("      ipv4 watches  : %d\n",
				AXA_P2H32(
					user->srvr.sra.watches.ipv4_cnt));
			printf("      ipv6 watches  : %d\n",
				AXA_P2H32(
					user->srvr.sra.watches.ipv6_cnt));
			printf("      dns watches   : %d\n",
				AXA_P2H32(
					user->srvr.sra.watches.dns_cnt));
			printf("      ch watches    : %d\n",
				AXA_P2H32(
					user->srvr.sra.watches.ch_cnt));
			printf("      err watches   : %d\n",
				AXA_P2H32(
					user->srvr.sra.watches.err_cnt));
			break;
		case RAD:
			printf("      anomalies     : %d\n",
				AXA_P2H32(user->srvr.rad.an_obj_cnt));
			break;
		case BOTH:
			break;
	}
	printf("      rate-limiting : ");
	if (AXA_P2H64(user->ratelimit) == AXA_RLIMIT_OFF)
		printf("off\n");
	else
		printf("%"PRIu64"\n", AXA_P2H64(user->ratelimit));
	printf("      sampling      : %.2f%%\n",
			AXA_P2H64(user->sample) * .0001);

	if (mode == RAD && user->srvr.rad.an_obj_cnt > 0) {
		if (user->srvr.rad.an_obj_cnt >
			_AXA_STATS_MAX_USER_RAD_AN_OBJS) {
			printf("invalid rad anomaly object count: %u",
					user->srvr.rad.an_obj_cnt);
			return (bytes_printed);
		}

		printf("      loaded modules\n");
		p = (uint8_t *)user + sizeof (_axa_p_stats_user_t);
		for (an_objs_cnt = user->srvr.rad.an_obj_cnt; an_objs_cnt;
				an_objs_cnt--) {
			print_stats_user_an((_axa_p_stats_user_rad_an_t *)p);
			bytes_printed += sizeof(_axa_p_stats_user_rad_an_t);
			p += sizeof(_axa_p_stats_user_rad_an_t);
		}
	}

	printf("      packet counters\n");
	last_cnt_update.tv_sec = user->last_cnt_update.tv_sec;
	last_cnt_update.tv_usec = user->last_cnt_update.tv_usec;
	t = AXA_P2H32(last_cnt_update.tv_sec);
	tm_info = gmtime(&t);
	strftime(time_buf, sizeof (time_buf), "%Y-%m-%dT%H:%M:%SZ", tm_info);
	printf("      last updated  : %s (%s)\n", time_buf,
			convert_timeval(&last_cnt_update));
	printf("        filtered    : %"PRIu64"\n",
			AXA_P2H64(user->filtered));
	printf("        missed      : %"PRIu64"\n",
			AXA_P2H64(user->missed));
	printf("        collected   : %"PRIu64"\n",
			AXA_P2H64(user->collected));
	printf("        sent        : %"PRIu64"\n",
			AXA_P2H64(user->sent));
	printf("        rlimit      : %"PRIu64"\n",
			AXA_P2H64(user->rlimit));
	printf("        congested   : %"PRIu64"\n",
			AXA_P2H64(user->congested));

	bytes_printed += sizeof (_axa_p_stats_user_t);
	return (bytes_printed);
}

void
print_stats(_axa_p_stats_rsp_t *stats, uint32_t len)
{
	uint16_t user_objs_cnt;
	uint8_t *p;
	int q = 0;

	if (stats->version != _AXA_STATS_VERSION_ONE) {
		printf("server returned unknown stats protocol version %d\n",
				stats->version);
		return;
	}

	if (axa_debug != 0) {
		printf("    stats_len       : %ub\n", AXA_P2H32(len));
	}

	switch (stats->result) {
		case AXA_P_STATS_R_SUCCESS:
			printf("    success\n");
			break;
		case AXA_P_STATS_R_FAIL_NF:
			printf("    failed, user/sn not found\n");
			return;
		case AXA_P_STATS_R_FAIL_UNK:
			printf("    failed, unknown reason\n");
			return;
		default:
			printf("    unknown result code\n");
			return;
	}

	if (stats->sys_objs_cnt > 1) {
		printf("invalid stats response: too many sys objects (%u > 1)\n", stats->sys_objs_cnt);
		return;
	}

	if (stats->user_objs_cnt > _AXA_STATS_MAX_USER_OBJS) {
		printf("invalid stats response: too many user objects (%u > %u)\n", stats->user_objs_cnt, _AXA_STATS_MAX_USER_OBJS);
		return;
	}

	p = (uint8_t *)stats + sizeof(_axa_p_stats_rsp_t);
	if (stats->sys_objs_cnt == 1)
		print_stats_sys((_axa_p_stats_sys_t *)p);

	p += (stats->sys_objs_cnt * sizeof (_axa_p_stats_sys_t));
	for (user_objs_cnt = stats->user_objs_cnt; user_objs_cnt;
			user_objs_cnt--) {
		q = print_stats_user((_axa_p_stats_user_t *)p);
		p += q;
	}
}

void
print_kill(_axa_p_kill_t *kill, size_t len AXA_UNUSED)
{
	switch (kill->result) {
		case AXA_P_KILL_R_SUCCESS:
			printf("    success\n");
			break;
		case AXA_P_KILL_R_FAIL_NF:
			printf("    failed, %s not found\n",
					kill->mode == AXA_P_KILL_M_SN ?
					"serial number" : "user");
			break;
		case AXA_P_KILL_R_FAIL_UNK:
			printf("    failed, unknown reason\n");
			break;
	}
}
