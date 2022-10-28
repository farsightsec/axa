/*
 * Tunnel SIE data from an SRA or RAD server.
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

#ifndef SRATUNNEL_H
#define SRATUNNEL_H

#include <config.h>
#include <axa/client.h>
#include <axa/client_config.h>
#include <axa/axa_endian.h>
#include <axa/fields.h>
#include <axa/open_nmsg_out.h>
#include <axa/kickfile.h>

#include <nmsg.h>
#include <nmsg/base/defs.h>
#include <nmsg/base/packet.pb-c.h>

#include <net/ethernet.h>
#ifdef __linux
#include <netinet/ether.h>
#include <bsd/string.h>
#endif
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdlib.h>
#include <string.h>
#include <sysexits.h>
#include <sys/stat.h>
#include <unistd.h>

#define OUT_FLUSH_MS    10		/* flush output this often */

typedef struct arg arg_t;
struct arg {
	arg_t           *next;
	const char      *c;
};

typedef enum {
	SRA,
	RAD
} axa_mode_t;

/* forward.c */
void forward(void);

/* main.c */
void stop(int s) AXA_NORETURN;

/* output.c */
bool out_open(bool);
void out_close(void);
void out_flush(void);
void out_whit_nmsg(axa_p_whit_t *whit, size_t whit_len);
void out_whit_pcap(axa_p_whit_t *whit, size_t whit_len);

/* pidfile.c */
FILE *pidfile_open(void);
void pidfile_write(void);

/* print.c */
void print_op(bool always, bool sent, const axa_p_hdr_t *hdr, const void *body);
void print_bad_op(const char *adj);
void print_trace(void);
void print_missed(void);

/* server.c */
void disconnect(bool complain, const char *p, ...) AXA_PF(2,3);
void srvr_connect(void);
bool srvr_send(axa_tag_t tag, axa_p_op_t op, const void *b, size_t b_len);

/* signal.c */
void sigterm(int sig);

#ifdef SIGINFO
void siginfo(int);
#endif

#endif /* SRATUNNEL_H */
