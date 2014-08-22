/*
 * Advanced Exchange Access (AXA) protocol
 *	This protocol use network byte order to accomodate that SRA clients
 *	on a modest variety of 32-bit and 64-bit *BSD and Linux systems.
 *	It might need adjustment to accomodate clients on ARM and other
 *	platforms other than amd64 and x86.
 *
 *	These protocols should not allow the client ask for the server to
 *	run any program or do anything else that might change any permanent
 *	state on the server other than logging and accounting.
 *	A client should only be able to set its only filter criteria and
 *	receive packets and messags matching those criteria.  Other than
 *	inevitiable side channels such as system load, one client must
 *	not be able to affect any other client.  A client must treat the
 *	packets and messages it receives as pure data and not commands.
 *
 * This file is used outside the AXA programs.
 *
 *  Copyright (c) 2014 by Farsight Security, Inc.
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

#ifndef AXA_PROTOCOL_H
#define AXA_PROTOCOL_H

#include <sys/types.h>
#include <sys/poll.h>
#include <netinet/in.h>

#include <axa/socket.h>

#define _PK __attribute__ ((__packed__))

#define AXA_KEEPALIVE_SECS  30
#define AXA_KEEPALIVE_MS    (AXA_KEEPALIVE_SECS*1000)


/* Tags are opaque to SRA server except for AXA_TAG_NONE
 *	and that the server orders them like integers.
 */
typedef uint16_t	axa_tag_t;
#define AXA_TAG_NONE	0
#define AXA_TAG_MAX	((axa_tag_t)-1)


/* Define old versions for eventual "#ifdef AXA_P_VERSx". */
typedef uint8_t		axa_p_pvers_t;
#define AXA_P_PVERS1	1
#define AXA_P_PVERS	AXA_P_PVERS1
#define AXA_P_PVERS_MIN	AXA_P_PVERS1
#define AXA_P_PVERS_MAX	AXA_P_PVERS1


/* Choose a generally little endian byte.
 * This must not affect some values such as UDP port numbers and
 * IPv4 addresses which must be big endian except when they are
 * manipulated as numbers.
 * Hence, AXA_H2Pxx() stands for "AXA Host to Protocol..." */
#define AXA_H2P16(x)	htole16(x)
#define AXA_H2P32(x)	htole32(x)
#define AXA_H2P64(x)	htole64(x)
#define AXA_P2H16(x)	le16toh(x)
#define AXA_P2H32(x)	le32toh(x)
#define AXA_P2H64(x)	le64toh(x)


/* room for more than 2 full sized UDP packets */
#define AXA_P_MAX_BODY_LEN	(64*1024*3)

/* clients must authenticate within many seconds after connect(). */
#define AXA_AUTH_DELAY	30

/* This header starts all items in either direction.
 *	At 8 bytes, it is alignment friendly. */
typedef struct _PK {
	uint32_t	len;		/* including this header */
	axa_tag_t	tag;
	axa_p_pvers_t	pvers;
	uint8_t		op;
} axa_p_hdr_t;

/* Use a single address space of opcodes in both directions. */
typedef enum {
	AXA_P_OP_NOP	    =0,		/* no data */

	/* from SRA or RAD server to client */
	AXA_P_OP_HELLO	    =1,		/* axa_p_hello_t */
	AXA_P_OP_OK	    =2,		/* axa_p_result_t */
	AXA_P_OP_ERROR	    =3,		/* axa_p_result_t */
	AXA_P_OP_MISSED	    =4,		/* axa_p_missed_t */
	AXA_P_OP_WHIT	    =5,		/* axa_p_whit_t */
	AXA_P_OP_WLIST	    =6,		/* axa_p_wlist_t */
	AXA_P_OP_AHIT	    =7,		/* axa_p_ahit_t */
	AXA_P_OP_ALIST	    =8,		/* axa_p_alist_t */
	AXA_P_OP_CLIST	    =9,		/* axa_p_clist_t */

	/* from client to SRA or RAD server */
	AXA_P_OP_USER	    =129,	/* axa_p_user_t */
	AXA_P_OP_JOIN	    =130,	/* no data */
	AXA_P_OP_PAUSE	    =131,	/* no data */
	AXA_P_OP_GO	    =132,	/* no data */
	AXA_P_OP_WATCH	    =133,	/* axa_p_watch_t */
	AXA_P_OP_WGET	    =134,	/* no data */
	AXA_P_OP_ANOM	    =135,	/* axa_p_anom_t */
	AXA_P_OP_AGET	    =136,	/* no data */
	AXA_P_OP_STOP	    =137,	/* no data */
	AXA_P_OP_ALL_STOP   =138,	/* no data */
	AXA_P_OP_CHANNEL    =139,	/* axa_p_channel_t */
	AXA_P_OP_CGET	    =140,	/* no data */
	AXA_P_OP_OPT	    =141,	/* axa_p_opt_t */
	AXA_P_OP_ACCT	    =142,	/* no data */
} axa_p_op_t;


/* RAD and SRA servers start the client-server conversation with a
 * AXA_P_OP_HELLO annoucing the protocol versions they understand,
 * a version string, and an ID unique among connections to a single server.
 * Clients can include those IDs in AXA_P_OP_JOIN messages to flag
 * connections that are part of a bundle. */
typedef uint64_t axa_p_clnt_id_t;
typedef struct _PK {
	axa_p_clnt_id_t	id;
	axa_p_pvers_t	pvers_min;
	axa_p_pvers_t	pvers_max;
	char		str[512];	/* null terminated */
} axa_p_hello_t;

typedef struct _PK {
	axa_p_clnt_id_t	id;
} axa_p_join_t;

typedef struct _PK {
	uint8_t		op;		/* original axa_p_op_t */
	char		str[512];	/* null terminated */
} axa_p_result_t;

typedef struct _PK {
	uint64_t	input_dropped;
	uint64_t	dropped;
	uint64_t	sec_rlimited;
	uint64_t	day_rlimited;
	uint32_t	last_reported;
} axa_p_missed_t;

typedef struct _PK {
	char		name[64];	/* null terminated */
} axa_p_user_t;


typedef struct {char c[16];} axa_p_ch_buf_t;
typedef uint16_t axa_p_ch_t;
#define AXA_OP_CH_PREFIX "ch"
#define AXA_OP_CH_ALL	((axa_p_ch_t)-1)
#define AXA_OP_CH_ALLSTR "all"
#define AXA_OP_CH_MAX	4095

typedef enum {
	AXA_P_WHIT_NMSG =0,
	AXA_P_WHIT_IP	=1,
} axa_p_whit_enum_t;
typedef struct _PK {
	axa_p_ch_t	ch;		/* channel number */
	uint8_t		type;		/* axa_p_whit_enum_t */
	uint8_t		pad;		/* to 0 mod 4 */
} axa_p_whit_hdr_t;

typedef uint16_t		axa_nmsg_idx_t;
#define AXA_NMSG_IDX_RSVD	((axa_nmsg_idx_t)-16)
#define AXA_NMSG_IDX_NONE	(AXA_NMSG_IDX_RSVD+1)
#define AXA_NMSG_IDX_ERROR	(AXA_NMSG_IDX_RSVD+2)
#define AXA_NMSG_IDX_ALL_CH	(AXA_NMSG_IDX_RSVD+3)
typedef struct _PK {
	axa_p_whit_hdr_t mhdr;
	axa_nmsg_idx_t	field_idx;	/* triggering field index */
	axa_nmsg_idx_t	val_idx;	/* which value of field */
	axa_nmsg_idx_t	vid;		/* nmsg vendor ID */
	axa_nmsg_idx_t	type;		/* nmsg type */
	struct _PK {
	    uint32_t	    tv_sec;
	    uint32_t	    tv_nsec;
	} ts;
	uint8_t		msg[0];
} axa_p_whit_nmsg_hdr_t;

typedef struct _PK {
	axa_p_whit_hdr_t mhdr;
	struct _PK {
	    uint32_t	    tv_sec;
	    uint32_t	    tv_usec;
	} ts;
	uint32_t	orig_len;	/* original length on the wire */
} axa_p_whit_ip_hdr_t;

typedef	struct _PK {
	axa_p_whit_nmsg_hdr_t hdr;
# define AXA_P_WHIT_NMSG_MAX (3*(2<<16))    /* some nmsg have >1 DNS packet */
	uint8_t	    b[0];
}  axa_p_whit_nmsg_t;

typedef struct _PK {
	axa_p_whit_ip_hdr_t hdr;
# define AXA_P_WHIT_IP_MAX  (2<<16)	/* IPv6 can be bigger */
	uint8_t	    b[0];
} axa_p_whit_ip_t;

typedef union {
	axa_p_whit_hdr_t hdr;
	axa_p_whit_nmsg_t nmsg;
	axa_p_whit_ip_t	ip;
} axa_p_whit_t;
#define AXA_WHIT_MIN_LEN min(sizeof(axa_p_whit_ip_t),			\
			     sizeof(axa_p_whit_nmsg_t))
#define AXA_WHIT_MAX_LEN max(sizeof(axa_p_whit_ip_t)+AXA_P_WHIT_IP_MAX,	\
			     sizeof(axa_p_whit_nmsg_t)+AXA_P_WHIT_NMSG_MAX)

typedef enum {
	AXA_P_WATCH_IPV4    =1,
	AXA_P_WATCH_IPV6    =2,
	AXA_P_WATCH_DNS	    =3,
	AXA_P_WATCH_CH	    =4,
	AXA_P_WATCH_ERRORS  =5
} axa_p_watch_type_t;
typedef union {
	struct _PK in_addr  addr;
	struct _PK in6_addr addr6;
#	 define		 AXA_P_DOMAIN_LEN 255
	uint8_t		dns[AXA_P_DOMAIN_LEN];	/* DNS wire format */
	axa_p_ch_t	ch;
} axa_p_watch_pat_t;
typedef struct _PK {
	uint8_t		type;		/* axa_p_watch_type_t */
	uint8_t		prefix;		/* IP address only */
	uint8_t		is_wild;
	uint8_t		pad[1];		/* to 0 mod 4 */
	axa_p_watch_pat_t pat;
} axa_p_watch_t;

typedef struct _PK {
	axa_tag_t	cur_tag;
	uint8_t		pad[2];		/* to 0 mod 4 */
	axa_p_watch_t	w;
} axa_p_wlist_t;


#define AXA_OP_AN_PREFIX "an;"
typedef struct _PK {			/* anomaly name */
	char		c[32];		/* wastefully null terminated */
} axa_p_an_t;
typedef struct _PK {
	axa_p_an_t	an;
	char		parms[1024];	/* null terminated */
} axa_p_anom_t;

typedef struct _PK {
	axa_p_an_t	an;
	axa_p_whit_t	whit;
} axa_p_ahit_t;

typedef struct _PK {
	axa_tag_t	cur_tag;
	uint8_t		pad[2];		/* to 0 mod 4 */
	axa_p_anom_t	anom;
} axa_p_alist_t;

typedef struct _PK {
	axa_p_ch_t	ch;
	uint8_t		on;
} axa_p_channel_t;


typedef struct _PK {
	char		c[1024];	/* roughly MAXPATHLEN, null term */
} axa_p_chspec_t;

typedef struct _PK {
	axa_p_ch_t	ch;
	uint8_t		on;
	axa_p_chspec_t	spec;
} axa_p_clist_t;


typedef uint64_t	axa_rlimit_t;
#define AXA_RLIMIT_MAX	(1000*1000*1000)
#define AXA_RLIMIT_OFF	(AXA_RLIMIT_MAX+1)
#define AXA_RLIMIT_NA	((axa_rlimit_t)-1)
#define AXA_RLIMIT_MAX_SECS (24*60*60)
typedef struct _PK {
	axa_rlimit_t	max_pkts_per_sec;
	axa_rlimit_t	cur_pkts_per_sec;
	axa_rlimit_t	max_pkts_per_day;
	axa_rlimit_t	cur_pkts_per_day;
	axa_rlimit_t	report_secs;
} axa_p_rlimit_t;

typedef enum {
	AXA_P_OPT_DEBUG    =0,
	AXA_P_OPT_RLIMIT   =1,
} axa_p_opt_type_t;

typedef struct _PK {
	uint8_t		type;
	uint8_t		pad[7];		/* to 0 mod 8 for axa_p_rlimit_t */
	union {
		uint32_t	debug;
		axa_p_rlimit_t	rlimit;
	} u;
} axa_p_opt_t;



typedef union axa_p_body {
	axa_p_hello_t	hello;
	axa_p_result_t	result;
	axa_p_missed_t	missed;
	axa_p_whit_t	whit;
	axa_p_wlist_t	wlist;
	axa_p_ahit_t	ahit;
	axa_p_alist_t	alist;

	axa_p_user_t    user;
	axa_p_join_t    join;
	axa_p_watch_t	watch;
	axa_p_anom_t	anom;
	axa_p_channel_t	channel;
	axa_p_clist_t	clist;
	axa_p_opt_t	opt;

	uint8_t		b[1];
} axa_p_body_t;


/* Data passed from ssh proxy. */
typedef struct {			/* not packed because it is local */
	char		magic[16];
#	 define AXA_PROXY_SSH_MAGIC "PROXY_SSH_0"
	axa_socku_t	su;
	char		peer[INET6_ADDRSTRLEN];
	axa_p_user_t	user;
} axa_proxy_ssh_t;


#undef _PK
#endif /* AXA_PROTOCOL_H */
