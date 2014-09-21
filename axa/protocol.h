/*
 * Advanced Exchange Access (AXA) protocol definitions
 *
 *  Copyright (c) 2014 by Farsight Security, Inc.
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

/*! \file protocol.h
 *  \brief AXA protocol datatypes and macros.
 *
 *  This file contains the AXA protocol datatypes and macros.
 *  This protocol uses network byte order to accomodate that SRA clients
 *  on a modest variety of 32-bit and 64-bit *BSD and Linux systems.
 *  It might need adjustment to accomodate clients on ARM and other
 *  platforms other than amd64 and x86.
 */

#include <sys/types.h>
#include <sys/poll.h>
#include <netinet/in.h>

#include <axa/socket.h>

/** minimize memory required */
#define _PK __attribute__ ((__packed__))

/** ah ah ah ah staying alive */
#define AXA_KEEPALIVE_SECS  30
/** ah ah ah ah staying alive (in ms) */
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
 *  Tags are opaque to SRA server except for AXA_TAG_NONE and that the server 
 *  orders them like integers.
 */
typedef uint16_t	axa_tag_t;

/** no tag */
#define AXA_TAG_NONE	0
/** maximum tag */
#define AXA_TAG_MAX	((axa_tag_t)-1)
/**
 *  Convert tag from protocol to host order
 *
 *  \param[in] t tag
 *
 *  \return host ordered tag
 */
#define AXA_P2H_TAG(t)	AXA_P2H16(t)

/**
 *  Convert tag from host to protocol order
 *
 *  \param[in] t tag
 *
 *  \return protocol ordered tag
 */
#define AXA_H2P_TAG(t)	AXA_H2P16(t)

/** define old versions for eventual "#ifdef AXA_P_VERSx" */
typedef uint8_t		axa_p_pvers_t;
/** protocol version 1 */
#define AXA_P_PVERS1	1
/** current protocol version */
#define AXA_P_PVERS	AXA_P_PVERS1
/** maximum protocol version */
#define AXA_P_PVERS_MIN	AXA_P_PVERS1
/** minimum protocol version */
#define AXA_P_PVERS_MAX	AXA_P_PVERS1


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
 *  \return protocol ordered 16-bit value
 */
#define AXA_H2P16(x)	htole16(x)
/**
 *  AXA host to protocol 32-bit
 *
 *  \param x value to convert
 *
 *  \return protocol ordered 32-bit value
 */
#define AXA_H2P32(x)	htole32(x)
/**
 *  AXA host to protocol 64-bit
 *
 *  \param x value to convert
 *
 *  \return protocol ordered 64-bit value
 */
#define AXA_H2P64(x)	htole64(x)
/**
 *  AXA protocol to host 16-bit
 *
 *  \param x value to convert
 *
 *  \return host ordered 16-bit value
 */
#define AXA_P2H16(x)	le16toh(x)
/**
 *  AXA protocol to host 32-bit
 *
 *  \param x value to convert
 *
 *  \return host ordered 32-bit value
 */
#define AXA_P2H32(x)	le32toh(x)
/**
 *  AXA protocol to host 64-bit
 *
 *  \param x value to convert
 *
 *  \return host ordered 64-bit value
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


/** Room for more than two full sized UDP packets. */
#define AXA_P_MAX_BODY_LEN	(64*1024*3)

/** Clients must authenticate within many seconds after connect(). */
#define AXA_AUTH_DELAY	30

/**
 *  AXA protocol header
 *  This header starts all conversations in either direction.
 *  At 8 bytes, it is alignment friendly.
 */
typedef struct _PK {
	uint32_t	len;		    /**< total msg length including this header */
    /**
     *  A tag is a 16-bit identifier used to uniquely "tag" specific events
     *  during the lifetime of an AXA session. To refer to these events, the 
     *  client or server will use the tag. Some AXA messages do not require 
     *  tags, in that case the tag field should be 0. Required tags must be 
     *  unique during the lifetime of the corresponding client request. Some 
     *  client requests such as a "watch" can last indefinitely and will 
     *  elicit many server responses all with the same tag.
     */
    axa_tag_t	tag;
	axa_p_pvers_t	pvers;      /**< protocol version */
	uint8_t		op;             /**< op code */
} axa_p_hdr_t;

/**
 * AXA protocol opcodes
 * Use a single address space of opcodes in both directions.
 */
typedef enum {
	AXA_P_OP_NOP	    =0,		/**< no data */

	/** from SRA or RAD server to client */
	AXA_P_OP_HELLO	    =1,		/**< axa_p_hello_t */
	AXA_P_OP_OK	        =2,		/**< axa_p_result_t */
	AXA_P_OP_ERROR	    =3,		/**< axa_p_result_t */
	AXA_P_OP_MISSED	    =4,		/**< axa_p_missed_t */
	AXA_P_OP_WHIT	    =5,		/**< axa_p_whit_t */
	AXA_P_OP_WLIST	    =6,		/**< axa_p_wlist_t */
	AXA_P_OP_AHIT	    =7,		/**< axa_p_ahit_t */
	AXA_P_OP_ALIST	    =8,		/**< axa_p_alist_t */
	AXA_P_OP_CLIST	    =9,		/**< axa_p_clist_t */

	/** from client to SRA or RAD server */
	AXA_P_OP_USER	    =129,	/**< axa_p_user_t */
	AXA_P_OP_JOIN	    =130,	/**< no data */
	AXA_P_OP_PAUSE	    =131,	/**< no data */
	AXA_P_OP_GO	        =132,	/**< no data */
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
} axa_p_op_t;

/** AXA protocol client ID */
typedef uint64_t axa_p_clnt_id_t;

/**
 *  RAD and SRA servers start the client-server conversation with a
 *  AXA_P_OP_HELLO annoucing the protocol versions that the server understands,
 *  a version string, and an ID unique among connections to a single server.
 *  Clients can include those IDs in AXA_P_OP_JOIN messages to flag
 *  connections that are part of a bundle.
 *  Because AXA_P_OP_HELLO is sent before the client has said anything and so
 *  declared its protocol version,
 *  AXA_P_OP_HELLO must remain the same in all protocol versions.
 */
typedef struct _PK {
	axa_p_clnt_id_t	id;         /**< ID */
	axa_p_pvers_t	pvers_min;  /**< minimum protocol version accepted */
	axa_p_pvers_t	pvers_max;  /**< maximum protocol version accepted */
    /**
     *  Human readable string containing name and version of the SRA or RAD 
     *  server (variable length string up to 512 bytes including terminating 
     *  NULL).
     */
    char		str[512];
} axa_p_hello_t;

/** AXA protocol join */
typedef struct _PK {
	axa_p_clnt_id_t	id;         /**< ID */
} axa_p_join_t;

/** AXA protocol result */
typedef struct _PK {
	uint8_t		op;		                /**< original axa_p_op_t */
#define	AXA_P_RESULT_LEN 512            /**< length of result string */
    /**
     *  Human readable string containing error message why the request failed
     *  (variable length string up to 512 bytes including terminating  NULL).
     */
	char		str[AXA_P_RESULT_LEN];
} axa_p_result_t;

/** AXA protocol missed */
typedef struct _PK {
    /**
     *  The number of data lost or dropped by the server because it was too 
     *  busy. For an SRA server, it is the total nmsg and pcap messages lost 
     *  because the SRA server was too busy or because of network congestion 
     *  between the SRA server and nmsg sources.
     */
	uint64_t	input_dropped;
    /**
     *  The number of SRA messages discarded by the server instead of being 
     *  transmitted, because of congestion on the server-to-client connection.
     */
	uint64_t	dropped;
    /**
     *  The number of SRA messages discarded by the server because of 
     *  per-second rate limiting.
     */
	uint64_t	sec_rlimited;
	uint64_t	unused;         /**< reserved */
	uint32_t	last_reported;  /**< UNIX epoch of the previous report */
} axa_p_missed_t;

/** AXA protocol user */
typedef struct _PK {
    /**
     *  Human readable string containing user-name (variable length string up
     *  to 64 bytes including terminating NULL).
     */
	char		name[64];
} axa_p_user_t;

/** AXA protocol channel buffer, holds human readable channel string */
typedef struct {
    char c[16];                 /**< channel string */
} axa_p_ch_buf_t;
/** AXA protocol channel, holds binary channel number */
typedef uint16_t axa_p_ch_t;
/** SIE channel prefix */
#define AXA_OP_CH_PREFIX "ch"
/** shorthand for "all channels", binary number */
#define AXA_OP_CH_ALL	((axa_p_ch_t)-1)
/** shorthand for "all channels", string */
#define AXA_OP_CH_ALLSTR "all"
/** maximum channel number */
#define AXA_OP_CH_MAX	4095

/**
 *  Convert channel from protocol to host order
 *
 *  \param[in] ch channel
 *
 *  \return host ordered channel
 */
#define AXA_P2H_CH(ch)	AXA_P2H16(ch)

/**
 *  Convert channel from host to protocol order
 *
 *  \param[in] ch channel
 *
 *  \return protocol ordered channel
 */
#define AXA_H2P_CH(ch)	AXA_H2P16(ch)

/** AXA protocol watch hit enum */
typedef enum {
	AXA_P_WHIT_NMSG =0,     /**< nmsg */
	AXA_P_WHIT_IP	=1,     /**< IP */
} axa_p_whit_enum_t;

/** AXA protocol top level watch hit header */
typedef struct _PK {
	axa_p_ch_t	ch;		    /**< channel number */
	uint8_t		type;		/**< axa_p_whit_enum_t */
	uint8_t		pad;		/**< to 0 mod 4 */
} axa_p_whit_hdr_t;

/** nmsg index */
typedef uint16_t		axa_nmsg_idx_t;
/** reserved nmsg index */
#define AXA_NMSG_IDX_RSVD	((axa_nmsg_idx_t)-16)
/** no nmsg index */
#define AXA_NMSG_IDX_NONE	(AXA_NMSG_IDX_RSVD+1)
/** nmsg index error */
#define AXA_NMSG_IDX_ERROR	(AXA_NMSG_IDX_RSVD+2)
/** nmsg index all channels */
#define AXA_NMSG_IDX_ALL_CH	(AXA_NMSG_IDX_RSVD+3)

/**
 *  Convert index from protocol to host order
 *
 *  \param[in] idx index
 *
 *  \return host ordered index
 */
#define AXA_P2H_IDX(idx)	AXA_P2H16(idx)

/**
 *  Convert index from host to protocol order
 *
 *  \param[in] idx index
 *
 *  \return protocol ordered index
 */
#define AXA_H2P_IDX(idx)	AXA_H2P16(idx)

/** AXA protocol watch hit nmsg header */
typedef struct _PK {
	axa_p_whit_hdr_t mhdr;              /**< top level watch hit header */
	axa_nmsg_idx_t	field_idx;	        /**< triggering field index */
	axa_nmsg_idx_t	val_idx;	        /**< which value of field */
	axa_nmsg_idx_t	vid;		        /**< nmsg vendor ID */
	axa_nmsg_idx_t	type;		        /**< nmsg type */
	struct _PK {
	    uint32_t	    tv_sec;         /**< seconds */
	    uint32_t	    tv_nsec;        /**< nanoseconds */
	} ts;                               /**< timestamp */
	uint8_t		msg[0];                 /**< the message */
} axa_p_whit_nmsg_hdr_t;

/** AXA protocol watch hit IP header */
typedef struct _PK {
	axa_p_whit_hdr_t mhdr;              /**< top level watch hit header */
    /** timestamp */
	struct _PK {
	    uint32_t	    tv_sec;         /**< seconds */
	    uint32_t	    tv_usec;        /**< microseconds */
	} tv;                               /**< timestamp */
	uint32_t	ip_len;		            /**< packet length on the wire */
} axa_p_whit_ip_hdr_t;

/** AXA protocol watch hit nmsg */
typedef	struct _PK {
	axa_p_whit_nmsg_hdr_t hdr;          /**< watch hit nmsg header */
# define AXA_P_WHIT_NMSG_MAX (3*(2<<16))    /**< some nmsg have >1 DNS packet */
    /**
     * start of message body (if not empty)
     */
	uint8_t	    b[0];                   
}  axa_p_whit_nmsg_t;

/** AXA protocol watch hit IP */
typedef struct _PK {
	axa_p_whit_ip_hdr_t hdr;             /**< watch hit IP header */
# define AXA_P_WHIT_IP_MAX  (2<<16)	        /**< IPv6 can be bigger */
	uint8_t	    b[0];                   /**< message body pointer */
} axa_p_whit_ip_t;

/** AXA protocol watch hit */
typedef union {
	axa_p_whit_hdr_t hdr;               /**< top level watch hit header */
	axa_p_whit_nmsg_t nmsg;             /**< watch hit nmsg header */
	axa_p_whit_ip_t	ip;                 /**< watch hit IP header */
} axa_p_whit_t;

/** Smallest watch hit */
#define AXA_WHIT_MIN_LEN min(sizeof(axa_p_whit_ip_t),			\
			     sizeof(axa_p_whit_nmsg_t))
/** Largest watch hit */
#define AXA_WHIT_MAX_LEN max(sizeof(axa_p_whit_ip_t)+AXA_P_WHIT_IP_MAX,	\
			     sizeof(axa_p_whit_nmsg_t)+AXA_P_WHIT_NMSG_MAX)

/** AXA protocol watch type */
typedef enum {
	AXA_P_WATCH_IPV4    =1,             /**< watch IPv4 */
	AXA_P_WATCH_IPV6    =2,             /**< watch IPv6 */
	AXA_P_WATCH_DNS	    =3,             /**< watch DNS */
	AXA_P_WATCH_CH	    =4,             /**< watch channel */
	AXA_P_WATCH_ERRORS  =5              /**< watch errors */
} axa_p_watch_type_t;

/** AXA protocol watch pattern */
typedef union {
	struct in_addr  addr;           /**< IPv4 address */
	struct in6_addr addr6;          /**< IPv6 address */
#	 define		 AXA_P_DOMAIN_LEN 255   /**< max length of a domain name */
	uint8_t		dns[AXA_P_DOMAIN_LEN];	/**< DNS wire format */
	axa_p_ch_t	ch;                     /**< channel */
} axa_p_watch_pat_t;

/** AXA protocol watch */
typedef struct _PK {
	uint8_t		type;		            /**< axa_p_watch_type_t */
	uint8_t		prefix;		            /**< IP address only */
	uint8_t		flags;                  /**< flags */
#define	 AXA_P_WATCH_FG_WILD	0x01	/**< valid for domains only */
#define	 AXA_P_WATCH_FG_SHARED	0x02    /**< shared */
#define	 AXA_P_WATCH_STR_SHARED "shared"/**< shared string */
	uint8_t		pad;		            /**< to 0 mod 4 */
	axa_p_watch_pat_t pat;              /**< watch pattern */
} axa_p_watch_t;

/** AXA protocol watch list */
typedef struct _PK {
	axa_tag_t	cur_tag;                /**< current tag of watch */
	uint8_t		pad[2];		            /**< to 0 mod 4 */
	axa_p_watch_t	w;                  /**< watch format */
} axa_p_wlist_t;

/**< @cond */
#define AXA_OP_AN_PREFIX "an;"
/**< @endcond */

/** AXA protocol anomaly name */
typedef struct _PK {			        /**< anomaly name */
	char		c[32];		            /**< wastefully null terminated */
} axa_p_an_t;

/** AXA protocol anomaly */
typedef struct _PK {
	axa_p_an_t	an;                     /**< anomaly */
	char		parms[1024];	        /**< parameters, null terminated */
} axa_p_anom_t;

/** AXA protocol anomaly watch hit */
typedef struct _PK {
	axa_p_an_t	an;                     /**< anomaly */
	axa_p_whit_t	whit;               /**< watch hit */
} axa_p_ahit_t;

/** AXA protocol anomaly list */
typedef struct _PK {
	axa_tag_t	cur_tag;                /**< current tag of watch */
	uint8_t		pad[2];		            /**< to 0 mod 4 */
	axa_p_anom_t	anom;               /**< anomaly */
} axa_p_alist_t;

/** AXA protocol channel enable/disable */
typedef struct _PK {
	axa_p_ch_t	ch;                     /**< channel number */
	uint8_t		on;                     /**< boolean, 1 for on, 0 for off */
} axa_p_channel_t;

/** AXA protocol channel specification */
typedef struct _PK {
    /**
     * Human readable string specifying the channel. It often looks like an IP 
     * address or network interface name or SIE channel alias.
     */
	char		c[1024];	            
} axa_p_chspec_t;

/** AXA protocol channel list */
typedef struct _PK {
	axa_p_ch_t	ch;                     /**< channel (binary) */
    /**
     * Zero or non-zero to indicate that the SRA server is monitoring this 
     * channel.
     */
	uint8_t		on;                 
	axa_p_chspec_t	spec;               /**< channel (human readable) */
} axa_p_clist_t;

/** AXA rlimit */
typedef uint64_t	axa_rlimit_t;

/** maximum rlimit */
#define AXA_RLIMIT_MAX	(1000*1000*1000)
/** turn off rlimit */
#define AXA_RLIMIT_OFF	(AXA_RLIMIT_MAX+1)
/** rlimit doesn't apply */
#define AXA_RLIMIT_NA	((axa_rlimit_t)-1)
/** rlimit maximum seconds (one day) */
#define AXA_RLIMIT_MAX_SECS (24*60*60)

/** AXA protocol rlimit */
typedef struct _PK {
	axa_rlimit_t	max_pkts_per_sec;   /**< maximum packets/sec */
	axa_rlimit_t	cur_pkts_per_sec;   /**< current packets/sec */
	axa_rlimit_t	unused1;            /**< reserved */
	axa_rlimit_t	unused2;            /**< reserved */  
    /**
     * The minimum number of seconds between reports of rate limiting.  
     * It's effectively a rate limit on rate limit reports.
     */
	axa_rlimit_t	report_secs;        
} axa_p_rlimit_t;

/** AXA protocol options type */
typedef enum {
	AXA_P_OPT_DEBUG    =0,              /**< debugging */
	AXA_P_OPT_RLIMIT   =1,              /**< rate limiting */
} axa_p_opt_type_t;

/** AXA protocol options */
typedef struct _PK {
	uint8_t		type;                   /**< option type */
	uint8_t		pad[7];		            /**< to 0 mod 8 for axa_p_rlimit_t */
	union {
		uint32_t	debug;              /**< debugging */
		axa_p_rlimit_t	rlimit;         /**< rlimit */
	} u;                                /**< option: debugging/rate limiting */
} axa_p_opt_t;

/** AXA protocol body */
typedef union axa_p_body {
	axa_p_hello_t	hello;              /**< hello */
	axa_p_result_t	result;             /**< result */
	axa_p_missed_t	missed;             /**< missed */
	axa_p_whit_t	whit;               /**< watch hit */
	axa_p_wlist_t	wlist;              /**< watch hit list */
	axa_p_ahit_t	ahit;               /**< anomaly hit */
	axa_p_alist_t	alist;              /**< anomaly list */

	axa_p_user_t    user;               /**< user */
	axa_p_join_t    join;               /**< join */
	axa_p_watch_t	watch;              /**< watch */
	axa_p_anom_t	anom;               /**< anom */
	axa_p_channel_t	channel;            /**< channel */
	axa_p_clist_t	clist;              /**< clist */
	axa_p_opt_t	opt;                    /**< options */

	uint8_t		b[1];                   /**< ... */
} axa_p_body_t;

/**< @cond */
typedef struct {			    /**< not packed because it is local */
	char		magic[16];
#	 define AXA_PROXY_SSH_MAGIC "PROXY_SSH_0"
	axa_socku_t	su;
	char		peer[INET6_ADDRSTRLEN];
	axa_p_user_t	user;
} axa_proxy_ssh_t;
/**< @endcond */


#undef _PK
#endif /* AXA_PROTOCOL_H */
