/*
 * Advanced Exchange Access (AXA) protocol definitions
 *
 *  Copyright (c) 2014-2015 by Farsight Security, Inc.
 *
 * This file is used outside the AXA programs.
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

#ifndef AXA_PROTOCOL_H
#define AXA_PROTOCOL_H

/**
 *  \defgroup axa_protocol axa_protocol
 *
 * `axa_protocol` contains the AXA protocol data types and macros.
 *
 * This protocol uses network byte order to accommodate SRA clients
 * on a modest variety of 32-bit and 64-bit *BSD and Linux systems.
 *
 * It might need adjustment to accommodate clients on ARM and other
 * platforms other than amd64 and x86.
 *
 *  These protocols should not allow the client ask for the server to run
 *  any program or do anything else that might change any permanent state on
 *  the server other than logging and accounting.
 *
 *  A client should only be able to set its only filter criteria and
 *  receive packets and messages matching those criteria.  Other than
 *  inevitable side channels such as system load, one client must
 *  not be able to affect any other client.  A client must treat the
 *  packets and messages it receives as pure data and not commands.
 *
 * @{
 */

#include <sys/types.h>
#include <sys/poll.h>
#include <netinet/in.h>

#include <axa/socket.h>

/**
 *  Pack AXA structures in messages to make them the same for all platforms
 *  regardless of their word alignment restrictions.
 */
#define _PK __attribute__ ((__packed__))

/** Send an AXA_P_OP_NOP after this many seconds of silence */
#define AXA_KEEPALIVE_SECS  30
/** Send an AXA_P_OP_NOP after this many milliseconds of silence */
#define AXA_KEEPALIVE_MS    (AXA_KEEPALIVE_SECS*1000)


/**
 *  A tag is a 16-bit identifier used to uniquely "tag" specific events during
 *  the lifetime of an AXA session. To refer to these events, the client or
 *  server will use the tag. Some AXA messages do not require tags, in that
 *  case the tag field should be 0. Required tags must be unique during the
 *  lifetime of the corresponding client request. Some client requests such as
 *  a "watch" can last indefinitely and will elicit many server responses all
 *  with the same tag.
 *
 *  Tags are opaque to the SRA server except for AXA_TAG_NONE and
 *  that the server sorts or orders them like integers.
 */
typedef uint16_t	axa_tag_t;

#define AXA_TAG_NONE	0		/**< no tag */
#define AXA_TAG_MIN	1		/**< minimum tag */
#define AXA_TAG_MAX	((axa_tag_t)-1)	/**< maximum tag */

/**
 *  Convert tag from protocol to host byte order.
 *
 *  \param[in] t tag
 *
 *  \return host byte ordered tag
 */
#define AXA_P2H_TAG(t)	AXA_P2H16(t)

/**
 *  Convert tag from host to protocol byte order.
 *
 *  \param[in] t tag
 *
 *  \return protocol byte ordered tag
 */
#define AXA_H2P_TAG(t)	AXA_H2P16(t)

/** define old versions for eventual "#ifdef AXA_P_VERSx" */
typedef uint8_t		axa_p_pvers_t;
/** protocol version 1 */
#define AXA_P_PVERS1	1
/** current protocol version */
#define AXA_P_PVERS	AXA_P_PVERS1
/** maximum understood protocol version */
#define AXA_P_PVERS_MIN	AXA_P_PVERS1
/** minimum understood protocol version */
#define AXA_P_PVERS_MAX	AXA_P_PVERS1

/** a number of messages or seconds */
typedef uint64_t	axa_cnt_t;


/**
 *  Choose a generally little endian protocol.
 *  This must not affect some values such as UDP port numbers and
 *  IPv4 addresses which must be big endian except when they are
 *  manipulated as numbers.
 *  Hence, AXA_H2Pxx() stands for "AXA Host to Protocol..."
 */
#if 1   /**< 0=switch to big endian protocol for testing */
/**
 *  AXA host to protocol 16-bit
 *
 *  \param x value to convert
 *
 *  \return protocol byte ordered 16-bit value
 */
#define AXA_H2P16(x)	htole16(x)
/**
 *  AXA host to protocol 32-bit
 *
 *  \param x value to convert
 *
 *  \return protocol byte ordered 32-bit value
 */
#define AXA_H2P32(x)	htole32(x)
/**
 *  AXA host to protocol 64-bit
 *
 *  \param x value to convert
 *
 *  \return protocol byte ordered 64-bit value
 */
#define AXA_H2P64(x)	htole64(x)
/**
 *  AXA protocol to host 16-bit
 *
 *  \param x value to convert
 *
 *  \return host byte ordered 16-bit value
 */
#define AXA_P2H16(x)	le16toh(x)
/**
 *  AXA protocol to host 32-bit
 *
 *  \param x value to convert
 *
 *  \return host byte ordered 32-bit value
 */
#define AXA_P2H32(x)	le32toh(x)
/**
 *  AXA protocol to host 64-bit
 *
 *  \param x value to convert
 *
 *  \return host byte ordered 64-bit value
 */
#define AXA_P2H64(x)	le64toh(x)
#else
/**< @cond */
#define AXA_H2P16(x)    htobe16(x)
#define AXA_H2P32(x)    htobe32(x)
#define AXA_H2P64(x)    htobe64(x)
#define AXA_P2H16(x)    be16toh(x)
#define AXA_P2H32(x)    be32toh(x)
#define AXA_P2H64(x)    be64toh(x)
/**< @endcond */
#endif

/** room for more than two full sized UDP packets */
#define AXA_P_MAX_BODY_LEN	(64*1024*3)

/**
 *  Clients must authenticate themselves to the AXA server within this
 *  many seconds after connect().
 */
#define AXA_AUTH_DELAY	30

/**
 *  AXA protocol header.
 *
 *  This header starts all messages in either direction. At 8 bytes, it is
 *  alignment friendly.
 */
typedef struct _PK {
	uint32_t	len;		/**< total length including header */
	/**
	 *  A tag is a 16-bit identifier used to uniquely "tag" specific events
	 *  during the lifetime of an AXA session. To refer to these events,
	 *  the client or server will use the tag. Some AXA messages do not
	 *  use tags.  In those cases, the tag field should be 0.  Required
	 *  tags must be unique during the lifetime of the corresponding client
	 *  request. Some requests such as a "watch" last indefinitely and
	 *  can elicit many server responses all with the same tag.
	 */
	axa_tag_t	tag;
	axa_p_pvers_t	pvers;		/**< protocol version */
	uint8_t		op;		/**< op code */
} axa_p_hdr_t;

/**
 * AXA protocol opcodes
 * Use a single address space of opcodes in both directions.
 */
typedef enum {
	AXA_P_OP_NOP	    =0,		/**< no data */

	/** from SRA or RAD server to client */
	AXA_P_OP_HELLO	    =1,		/**< axa_p_hello_t */
	AXA_P_OP_OK	    =2,		/**< axa_p_result_t */
	AXA_P_OP_ERROR	    =3,		/**< axa_p_result_t */
	AXA_P_OP_MISSED	    =4,		/**< axa_p_missed_t */
	AXA_P_OP_WHIT	    =5,		/**< axa_p_whit_t */
	AXA_P_OP_WLIST	    =6,		/**< axa_p_wlist_t */
	AXA_P_OP_AHIT	    =7,		/**< axa_p_ahit_t */
	AXA_P_OP_ALIST	    =8,		/**< axa_p_alist_t */
	AXA_P_OP_CLIST	    =9,		/**< axa_p_clist_t */
	AXA_P_OP_MISSED_RAD =10,	/**< axa_p_missed_rad_t */
	AXA_P_OP_MGMT_GETRSP=11,	/**< axa_p_mgmt_t */

	/** from client to SRA or RAD server */
	AXA_P_OP_USER	    =129,	/**< axa_p_user_t */
	AXA_P_OP_JOIN	    =130,	/**< no data */
	AXA_P_OP_PAUSE	    =131,	/**< no data */
	AXA_P_OP_GO	    =132,	/**< no data */
	AXA_P_OP_WATCH	    =133,	/**< axa_p_watch_t */
	AXA_P_OP_WGET	    =134,	/**< no data */
	AXA_P_OP_ANOM	    =135,	/**< axa_p_anom_t */
	AXA_P_OP_AGET	    =136,	/**< no data */
	AXA_P_OP_STOP	    =137,	/**< no data */
	AXA_P_OP_ALL_STOP   =138,	/**< no data */
	AXA_P_OP_CHANNEL    =139,	/**< axa_p_channel_t */
	AXA_P_OP_CGET	    =140,	/**< no data */
	AXA_P_OP_OPT	    =141,	/**< axa_p_opt_t */
	AXA_P_OP_ACCT	    =142,	/**< no data */

	AXA_P_OP_RADU	    =143,	/**< no data */
	AXA_P_OP_MGMT_GET   =144,	/**< no data */
} axa_p_op_t;

/**
 *  The AXA client ID is assigned by AXA server and echoed by the client
 *  to the server to bundle TCP connections.
 */
typedef uint64_t axa_p_clnt_id_t;

/**
 *  RAD and SRA servers start the client-server conversation with a
 *  AXA_P_OP_HELLO announcing the protocol versions that the server understands,
 *  a version string, and an ID unique among connections to a single server.
 *  Clients can include those IDs in AXA_P_OP_JOIN messages to flag
 *  connections that are part of a bundle.
 *  Because AXA_P_OP_HELLO is sent before the client has said anything and so
 *  declared its protocol version, AXA_P_OP_HELLO must remain the same in
 *  all versions of the AXA protocol.
 */
typedef struct _PK {
	axa_p_clnt_id_t	id;		    /**< client ID for bundled TCP */
	axa_p_pvers_t	pvers_min;	/**< min protocol version accepted */
	axa_p_pvers_t	pvers_max;	/**< max protocol version accepted */
	/**
	 *  Human readable string containing name and version of the SRA or RAD
	 *  server.  It is a variable length string up to 512 bytes including
	 *  terminating  NULL.
	 */
	char		str[512];
} axa_p_hello_t;

/** AXA protocol join */
typedef struct _PK {
	axa_p_clnt_id_t	id;		/**< client ID originally from server */
} axa_p_join_t;

/** AXA protocol result */
typedef struct _PK {
	uint8_t		orig_op;	/**< original axa_p_op_t */
	/**
	 *  Human readable string containing an error, success, or other
	 *  about the recent operation in .op with the tag the header of
	 *  this message.  It is variable length string up to 512 bytes the
	 *  including terminating null.
	 */
	char		str[512];
} axa_p_result_t;

/** AXA protocol SRA missed data */
typedef struct _PK {
	/**
	 *  The number of packets (SIE messages or raw IP packets) lost in
	 *  the network between the source and the SRA server or dropped by
	 *  the SRA server because it was too busy.
	 */
	axa_cnt_t	missed;
	axa_cnt_t	dropped;	/**< by SRA client-server congestion */
	axa_cnt_t	rlimit;		/**< dropped by rate limiting */
	axa_cnt_t	filtered;	/**< total considered */
	uint32_t	last_report;	/**< UNIX epoch of previous report */
} axa_p_missed_t;

/** AXA protocol RAD missed data */
typedef struct _PK {
	axa_cnt_t	sra_missed;	    /**< missed by all SRA servers */
	axa_cnt_t	sra_dropped;	/**< for SRA client-server congestion */
	axa_cnt_t	sra_rlimit;	    /**< discarded to SRA rate limit */
	axa_cnt_t	sra_filtered;	/**< considered by SRA servers */
	axa_cnt_t	dropped;	    /**< for RAD client-server congestion */
	axa_cnt_t	rlimit;		    /**< discarded to RAD rate limit */
	axa_cnt_t	filtered;	    /**< considered by RAD modules */
	uint32_t	last_report;	/**< UNIX epoch of previous report */
} axa_p_missed_rad_t;

/** AXA protocol user name */
typedef struct _PK {
	 /** ASCII, variable length, null terminated user name */
	char		name[64];
} axa_p_user_t;

/**
 *  Null terminated ASCII string naming an SIE channel in configuration files,
 *  sratool commands, and sratunnel args.
 */
typedef struct {
	char c[16];			/**< channel string */
} axa_p_ch_buf_t;

/** SIE channel name prefix in configuration files, commands, and args */
#define AXA_OP_CH_PREFIX "ch"

/** a binary SIE channel number in the AXA protocol */
typedef uint16_t axa_p_ch_t;

/** "all SIE channels" in configuration files, commands, and args */
#define AXA_OP_CH_ALL	((axa_p_ch_t)-1)
/** "all SIE channels" in AXA protocol messages and some axalib functions */
#define AXA_OP_CH_ALLSTR "all"

/** maximum channel number */
#define AXA_OP_CH_MAX	4095

/**
 *  Convert binary channel number from protocol to host byte order
 *
 *  \param[in] ch channel
 *
 *  \return host byte ordered SIE channel number
 */
#define AXA_P2H_CH(ch)	AXA_P2H16(ch)

/**
 *  Convert channel number from host to protocol byte order
 *
 *  \param[in] ch channel
 *
 *  \return protocol byte ordered SIE channel number
 */
#define AXA_H2P_CH(ch)	AXA_H2P16(ch)


/** type of AXA watch "hit" being reported to the client */
typedef enum {
	AXA_P_WHIT_NMSG =0,		/**< NMSG or SIE message */
	AXA_P_WHIT_IP	=1,		/**< IP */
} axa_p_whit_enum_t;

/** AXA protocol header before all watch hits */
typedef struct _PK {
	axa_p_ch_t	ch;		/**< channel number */
	uint8_t		type;		/**< axa_p_whit_enum_t */
	uint8_t		pad;		/**< to 0 mod 4 */
} axa_p_whit_hdr_t;

/** NMSG (SIE) field or value index or a special flag */
typedef uint16_t		axa_nmsg_idx_t;
/** values >= than this are not NMSG indices but flags */
#define AXA_NMSG_IDX_RSVD	((axa_nmsg_idx_t)-16)
/** no NMSG index */
#define AXA_NMSG_IDX_NONE	(AXA_NMSG_IDX_RSVD+1)
/** the SIE packet made no sense */
#define AXA_NMSG_IDX_ERROR	(AXA_NMSG_IDX_RSVD+2)
/** the AXA message is a dark channel packet */
#define AXA_NMSG_IDX_DARK	(AXA_NMSG_IDX_RSVD+3)

/**
 *  Convert #axa_nmsg_idx_t index from protocol to host byte order
 *
 *  \param[in] idx index
 *
 *  \return host byte ordered index, vendor number, etc.
 */
#define AXA_P2H_IDX(idx)	AXA_P2H16(idx)

/**
 *  Convert #axa_nmsg_idx_t index from host to protocol byte order
 *
 *  \param[in] idx index
 *
 *  \return protocol byte ordered index
 */
#define AXA_H2P_IDX(idx)	AXA_H2P16(idx)

/** AXA protocol watch hit header before an NMSG message */
typedef struct _PK {
	axa_p_whit_hdr_t hdr;		/**< header for all watch hits */
	axa_nmsg_idx_t	field_idx;	/**< triggering field index */
	axa_nmsg_idx_t	val_idx;	/**< which value of field */
	axa_nmsg_idx_t	vid;		/**< NMSG vendor ID */
	axa_nmsg_idx_t	type;		/**< NMSG type */
	/** timestamp when the NMSG message was reported. */
	struct _PK {
		uint32_t    tv_sec;	/**< seconds */
		uint32_t    tv_nsec;	/**< nanoseconds */
	} ts;				/**< timestamp */
} axa_p_whit_nmsg_hdr_t;

/** AXA protocol watch hit header before an IP packet */
typedef struct _PK {
	axa_p_whit_hdr_t hdr;		/**< header for all watch hits */
	/** timestamp when the packet was captured */
	struct _PK {
		uint32_t    tv_sec;	/**< seconds */
		uint32_t    tv_usec;	/**< microseconds */
	} tv;				/**< timestamp */
	uint32_t	ip_len;		/**< packet length on the wire */
} axa_p_whit_ip_hdr_t;

/** AXA protocol watch hit before an NMSG message */
typedef	struct _PK {
	axa_p_whit_nmsg_hdr_t hdr;	/**< watch hit NMSG header */
#define AXA_P_WHIT_NMSG_MAX (3*(2<<16))	/**< some NMSGs have >1 DNS packet */
	uint8_t	    b[0];		/**< start of SIE message */
}  axa_p_whit_nmsg_t;

/** AXA protocol watch hit before an IP packet */
typedef struct _PK {
	axa_p_whit_ip_hdr_t hdr;	/**< watch hit IP header */
# define AXA_P_WHIT_IP_MAX  (2<<16)	/**< IPv6 can be bigger */
	uint8_t	    b[0];		/**< start of IP packet */
} axa_p_whit_ip_t;

/** generic AXA protocol watch hit */
typedef union {
	axa_p_whit_hdr_t    hdr;	/**< top level watch hit header */
	axa_p_whit_nmsg_t   nmsg;	/**< an NMSG message */
	axa_p_whit_ip_t	    ip;		/**< an IP packet */
} axa_p_whit_t;

/** Smallest watch hit */
#define AXA_WHIT_MIN_LEN min(sizeof(axa_p_whit_ip_t)+1,			\
			     sizeof(axa_p_whit_nmsg_t)+1)
/** Largest watch hit */
#define AXA_WHIT_MAX_LEN max(sizeof(axa_p_whit_ip_t)+AXA_P_WHIT_IP_MAX,	\
			     sizeof(axa_p_whit_nmsg_t)+AXA_P_WHIT_NMSG_MAX)


/** AXA protocol watch type */
typedef enum {
	AXA_P_WATCH_IPV4    =1,		/**< watch IPv4 */
	AXA_P_WATCH_IPV6    =2,		/**< watch IPv6 */
	AXA_P_WATCH_DNS	    =3,		/**< watch DNS */
	AXA_P_WATCH_CH	    =4,		/**< watch channel */
	AXA_P_WATCH_ERRORS  =5		/**< watch errors */
} axa_p_watch_type_t;

/** AXA protocol watch pattern */
typedef union {
	struct in_addr	addr;		/**< IPv4 address */
	struct in6_addr	addr6;		/**< IPv6 address */
#	 define		 AXA_P_DOMAIN_LEN 255	/**< max len of domain names */
	uint8_t		dns[AXA_P_DOMAIN_LEN];	/**< DNS wire format */
	axa_p_ch_t	ch;		/**< channel */
} axa_p_watch_pat_t;

/** AXA protocol watch */
typedef struct _PK {
	uint8_t		type;		/**< axa_p_watch_type_t */
	uint8_t		prefix;		/**< IP address only */
	uint8_t		flags;		/**< flags */
#define	 AXA_P_WATCH_FG_WILD	0x01	/**< DNS wild card */
#define	 AXA_P_WATCH_FG_SHARED	0x02    /**< DNS domain or RR is not private */
#define	 AXA_P_WATCH_STR_SHARED "shared"    /**< shared string */
	uint8_t		pad;		/**< to 0 mod 4 */
	axa_p_watch_pat_t pat;		/**< watch pattern */
} axa_p_watch_t;

/** AXA protocol watch list */
typedef struct _PK {
	axa_tag_t	cur_tag;	/**< current tag of watch */
	uint8_t		pad[2];		/**< to 0 mod 4 */
	axa_p_watch_t	w;		/**< one of the listed watches */
} axa_p_wlist_t;

/**< @cond */
#define AXA_OP_AN_PREFIX "an;"
/**< @endcond */

/** AXA protocol anomaly module name */
typedef struct _PK {			/**< anomaly module name */
	char		c[32];		/**< wastefully null terminated */
} axa_p_an_t;

/** AXA protocol anomaly module specified by RAD client */
typedef struct _PK {
	axa_p_an_t	an;		/**< anomaly module name */
	char		parms[1024];	/**< parameters, null terminated */
} axa_p_anom_t;

/** AXA protocol anomaly module hit */
typedef struct _PK {
	axa_p_an_t	an;		/**< module that detected the anomaly */
	axa_p_whit_t	whit;		/**< anomalous SIE message or packet */
} axa_p_ahit_t;

/** AXA protocol anomaly list */
typedef struct _PK {
	axa_tag_t	cur_tag;	/**< current tag of watch */
	uint8_t		pad[2];		/**< to 0 mod 4 */
	axa_p_anom_t	anom;		/**< a listed anomaly module */
} axa_p_alist_t;

/** AXA protocol channel enable/disable */
typedef struct _PK {
	axa_p_ch_t	ch;		/**< channel number */
	uint8_t		on;		/**< boolean, 1 for on, 0 for off */
} axa_p_channel_t;

/** AXA protocol channel specification */
typedef struct _PK {
	/**
	 * Human readable string specifying the channel. It often looks
	 * like an IP address or network interface name or SIE channel alias.
	 */
	char		c[1024];
} axa_p_chspec_t;

/** AXA protocol channel list */
typedef struct _PK {
	axa_p_ch_t	ch;		/**< channel (binary) */
	uint8_t		on;		/** < !=0 if on */
	axa_p_chspec_t	spec;		/**< channel (human readable) */
} axa_p_clist_t;

/** Request server's current trace value */
#define AXA_P_OPT_TRACE_REQ ((uint32_t)-1)

/** maximum rlimit */
#define AXA_RLIMIT_MAX	(1000*1000*1000)
/** Turn off a rate limit. */
#define AXA_RLIMIT_OFF	(AXA_RLIMIT_MAX+1)
/** A rate limit value that doesn't apply or is not being set */
#define AXA_RLIMIT_NA	((axa_cnt_t)-1)

/** AXA protocol rlimit */
typedef struct _PK {
	/**
	 *  When in an option AXA_P_OP_OPT message sent by the client,
	 *  request the server to send no more than this many AXA AXA_P_OP_WHIT
	 *  or AXA_P_OP_AHIT messages per second.  Use AXA_RLIMIT_OFF to
	 *  request no limit.  AXA_RLIMIT_NA to not change th
	 */
	axa_cnt_t	max_pkts_per_sec;
	/**
	 *  This is the current value of the server's rate limit counter.
	 *  The counter is incremented each time a relevant AXA message
	 *  is considered for sending to the client.  If the new value is
	 *  greater than the rate limit, the message dropped.  The counter
	 *  is reset every second.
	 */
	axa_cnt_t	cur_pkts_per_sec;
	axa_cnt_t	unused1;	/**< reserved */
	axa_cnt_t	unused2;	/**< reserved */
	/**
	 * The minimum number of seconds between reports of rate limiting.
	 * It is a rate limit on rate limit reports.
	 */
	axa_cnt_t	report_secs;
} axa_p_rlimit_t;

/** Request the output sampling ratio */
#define	AXA_P_OPT_SAMPLE_REQ	0
/** Request the output sampling ratio */
#define	AXA_P_OPT_SAMPLE_SCALE	10000
/** maximum scaled output sampling ratio */
#define	AXA_P_OPT_SAMPLE_MAX	(AXA_P_OPT_SAMPLE_SCALE*100)

/** Request the TCP buffer size ratio */
#define	AXA_P_OPT_SNDBUF_REQ	0
/** TCP buffer minimum window size */
#define	AXA_P_OPT_SNDBUF_MIN	1024

/** AXA protocol options type */
typedef enum {
	AXA_P_OPT_TRACE	    =0,		/**< server tracing level */
	AXA_P_OPT_RLIMIT    =1,		/**< server rate limiting */
	AXA_P_OPT_SAMPLE    =2,		/**< sample an output stream. */
	AXA_P_OPT_SNDBUF    =3,		/**< set TCP buffer or window size */
} axa_p_opt_type_t;

/** AXA protocol options */
typedef struct _PK {
	uint8_t		type;		/**< option type */
	uint8_t		pad[7];		/**< to 0 mod 8 for axa_p_rlimit_t */
    /** option union */
	union axa_p_opt_u {
		uint32_t	trace;	    /**< AXA_P_OPT_TRACE: tracing level */
		axa_p_rlimit_t	rlimit;	/**< AXA_P_OPT_RLIMIT rate limits */
		uint32_t	sample;	    /**< AXA_P_OPT_SAMPLE percent*1000 */
		uint32_t	bufsize;    /**< AXA_P_OPT_SNDBUF bytes */
	} u;                        /**< holds actual option */
} axa_p_opt_t;


/** AXA protocol body */
typedef union {
	axa_p_hello_t	hello;		/**< hello to client */
	axa_p_result_t	result;		/**< result of client request */
	axa_p_missed_t	missed;		/**< report missed data by SRA */
	axa_p_whit_t	whit;		/**< watch hit */
	axa_p_wlist_t	wlist;		/**< list an watch */
	axa_p_ahit_t	ahit;		/**< anomaly hit */
	axa_p_alist_t	alist;		/**< list an anomaly */
	axa_p_clist_t	clist;		/**< channel list */
	axa_p_missed_rad_t missed_rad;	/**< report missed data by RAD*/

	axa_p_user_t    user;		/**< tell server which user */
	axa_p_join_t    join;		/**< bundle TCP */
	axa_p_watch_t	watch;		/**< ask for a watch on the server */
	axa_p_anom_t	anom;		/**< ask anomaly detection */
	axa_p_channel_t	channel;	/**< enable or disable a channel */
	axa_p_opt_t	opt;		/**< options */

	uint8_t		b[1];		/**< ... */
} axa_p_body_t;

/**< @cond */
/* Handshake from the program run by sshd, axaproxy, to srad or radd. */
typedef struct {			/**< not packed because it is local */
	char		magic[16];
#	 define AXA_PROXY_SSH_MAGIC "PROXY_SSH_0"
	axa_socku_t	su;
	char		peer[INET6_ADDRSTRLEN];
	axa_p_user_t	user;
} axa_proxy_ssh_t;
/**< @endcond */

/**@}*/

typedef struct axa_p_mgmt_user {
	axa_p_user_t 		user;		/** user name */
	struct timeval 		connected_since;/** logged in since */
	axa_cnt_t		filtered;	/** total packets filtered */
	axa_cnt_t		missed;		/** lost before filtering */
	axa_cnt_t		collected;	/** captured by filters */
	axa_cnt_t		sent;		/** sent to client */
	axa_cnt_t		rlimit;		/** lost to rate limiting */
	axa_cnt_t		congested;	/** lost to server->client */

	struct axa_p_mgmt_user 	*next;		/** next user */
} axa_p_mgmt_user_t;

typedef struct {
	float			load[3];	/** load avg */
	float			cpu_usage;	/** cpu usage */
	uint32_t		uptime;		/** system uptime */
	uint32_t		starttime;	/** process start time */
	uint32_t 		fd_sockets;     /** number of socket FDs */
	uint32_t 		fd_pipes;       /** number of pipe FDs */
	uint32_t 		fd_anon_inodes; /** number of anon_inode FDs */
	uint32_t 		fd_other;      	/** number of other FDs */
	long long unsigned int	vmsize;		/** total program size */
	long long unsigned int	vmrss;		/** resident set size */

	axa_p_mgmt_user_t	*users;		/** users list */
} axa_p_mgmt_t;

#undef _PK
#endif /* AXA_PROTOCOL_H */
