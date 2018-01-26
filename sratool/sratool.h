/*
 * SIE Remote Access (SRA) ASCII tool definitions
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

#ifndef SRATOOL_H
#define SRATOOL_H

#include <wdns.h>

#include <config.h>
#include <axa/axa_endian.h>
#include <axa/wire.h>
#include <axa/fields.h>
#include <axa/dns_walk.h>
#include <axa/client.h>
#include <axa/client_config.h>
#include <axa/open_nmsg_out.h>

#include <nmsg/vendors.h>
#include <nmsg/sie/defs.h>
#include <nmsg/base/defs.h>
#include <nmsg/base/dnsqr.pb-c.h>
#include <nmsg/sie/newdomain.pb-c.h>
#include <nmsg/base/packet.pb-c.h>

#include <arpa/nameser.h>
#include <errno.h>
#include <fcntl.h>
#include <net/ethernet.h>
#ifdef __linux
#include <netinet/ether.h>
#endif
#include <limits.h>
#include <signal.h>
#include <stdlib.h>
#include <string.h>
#ifdef __linux
#include <bsd/string.h>                 /* for strlcpy() */
#endif
#include <sysexits.h>
#include <sys/stat.h>
#include <unistd.h>

#include <histedit.h>
#include <pwd.h>
#include <math.h>


extern axa_p_hdr_t recv_hdr;
extern axa_p_body_t *recv_body;
extern size_t recv_len;

extern uint verbose;

#define NMSG_LEADER  "  "
#define NMSG_LEADER2 "   "


typedef struct cmd_tbl_entry cmd_tbl_entry_t;

/* -1=display help message, 0=command failed, 1=success */
typedef int cmd_t (axa_tag_t tag, const char *arg, const cmd_tbl_entry_t *ce);

extern void clear_prompt(void);

/* cmd.c */
#define MAX_IN_FILES 10

/*
 *  Simple way to subtract timeval based timers, subtracts `uvp` from `tvp`.
 *
 *  \param[in] tvp pointer to timeval structure (first value)
 *  \param[in] uvp pointer to timeval structure (second value)
 *  \param[out] vvp pointer to timeval (result timeval)
 */
#define PTIMERSUB(tvp, uvp, vvp)                                \
do {                                                            \
	(vvp)->tv_sec  = (tvp)->tv_sec  - (uvp)->tv_sec;        \
	(vvp)->tv_usec = (tvp)->tv_usec - (uvp)->tv_usec;       \
	if ((vvp)->tv_usec < 0) {                               \
		(vvp)->tv_sec--;                                \
		(vvp)->tv_usec += 1000000;                      \
	}                                                       \
} while (0)

typedef enum {
	SRA,
	RAD,
	BOTH
} axa_mode_t;

bool do_cmds(const char *cmd_buf);
void history_get_savefile(void);
const char *el_prompt(EditLine *e AXA_UNUSED);
void clear_prompt(void);
void reprompt(void);
int getcfn(EditLine *e AXA_UNUSED, char *buf);
void AXA_NORETURN usage(void);
int version_cmd(axa_tag_t tag AXA_UNUSED, const char *arg  AXA_UNUSED,
		const cmd_tbl_entry_t *ce AXA_UNUSED);
void error_help_cmd(axa_tag_t tag, const char *arg);

/* error.c */
void error_close(bool cmd_error);
void error_msg(const char *p, ...)  AXA_PF(1,2);

/* infile.c */
typedef struct input_files {
	uint    lineno;
	FILE    *f;
	char    *name;
	char    *buf;
	size_t  buf_size;
}in_files_t;
void close_in_file_cur(void);
void close_in_files(void);

/* io.c */
void io_wait(bool cmds_ok, bool once, time_t wait_ms);

/* main.c */
void AXA_NORETURN stop(int status);

/* output.c */
time_t out_flush_ck(const struct timeval *now, time_t delay);
void out_flush(void);
void out_close(bool announce);
bool out_error_ok(void);
void AXA_PF(1,2) out_error(const char *p, ...);
bool out_whit_nmsg(axa_p_whit_t *whit, size_t whit_len);
void out_ip_pcap_file(const uint8_t *pkt, size_t caplen, size_t len,
		const struct timeval *tv);
void out_ip_pcap_inject(const uint8_t *pkt, size_t caplen);
bool out_whit_pcap(axa_p_whit_t *whit, size_t whit_len);
axa_w2n_res_t whit2nmsg(nmsg_message_t *msgp, axa_p_whit_t *whit,
		size_t whit_len);

/* print.c */
void count_print(bool always);
void print_whit(axa_p_whit_t *whit, size_t whit_len, const char *title_sep,
		const char *title);
void print_ahit(void);
void print_channel(void);
void wlist_alist(void);
void print_raw(const uint8_t *pkt, size_t pkt_len);
bool print_dns_pkt(const uint8_t *data, size_t data_len, const char *str);
void print_raw_ip(const uint8_t *data, size_t data_len, axa_p_ch_t ch);
void print_stats(_axa_p_stats_rsp_t *stats, size_t len);
void print_kill(_axa_p_kill_t *kill, size_t len);

/* server.c */
void read_srvr(void);
int srvr_send(axa_tag_t tag, axa_p_op_t op, const void *b, size_t b_len);
void disconnect(bool announce);

/* signal.c */
void sigint(int sig AXA_UNUSED);
void sigterm(int sig AXA_UNUSED);

/* timer.c */
void convert_seconds(uint32_t seconds, uint32_t *d, uint32_t *h, uint32_t *m,
		uint32_t *s);
const char *convert_timeval(struct timeval *t);

#endif /* SRATOOL_H */
