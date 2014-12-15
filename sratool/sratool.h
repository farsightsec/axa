/*
 * SIE Remote Access (SRA) ASCII tool definitions
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

#ifndef SRATOOL_H
#define SRATOOL_H

#include <wdns.h>

#include <config.h>
#include <axa/wire.h>
#include <axa/fields.h>


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

extern void error_msg(const char *p, ...)  AXA_PF(1,2);

extern void print_raw(const uint8_t *pkt, size_t pkt_len);
extern bool print_dns_pkt(const uint8_t *data, size_t data_len,
			  const char *str);
extern void print_raw_ip(const uint8_t *data, size_t data_len,
			 const axa_p_whit_t *whit);


#endif /* SRATOOL_H */
