/*
 * Advanced Exchange Access (AXA) semantics for DNS packets and fields
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

#ifndef AXA_DNS_WALK_H
#define AXA_DNS_WALK_H

/**
 *  \defgroup axa_dns_walk axa_dns_walk
 *
 *  `dns_walk` facility takes a DNS packet or rdata field, additional
 *  information if required, and a set of functions that should be applied
 *  to parts of the packet or rdata.  The functions usually make decisions
 *  based on the contents (i.e.. filter it).  Domains are assembled by
 *  combining fragments of "compressed" domains.  Parts that are uninteresting
 *  for filter, such as MX precedence values, are skipped.
 *
 * @{
 */

#include <axa/axa.h>

/** A pointer to DNS data */
typedef const uint8_t axa_walkb_t;

/** DNS section name */
typedef const char axa_walks_t;

/** The context of a domain. */
typedef enum {
	AXA_WALK_DOM_QUESTION,		/**< DNS question */
	AXA_WALK_DOM_OWNER,		    /**< rdata owner domain */
	AXA_WALK_DOM_RDATA1,		/**< 1st or only domain in rdata */
	AXA_WALK_DOM_RDATA2,		/**< 2nd rdata domain in such as SOA */
} axa_walk_dom_t;

/** list of callback functions */
typedef const struct axa_walk_ops axa_walk_ops_t;

/**
 *  Callback function to deal with an error encountered while parsing a DNS
 *  packet or rdata, usually by printing or logging a message.
 *
 *  \param[in] ctxt DNS Walk caller's context
 *  \param[in] p printf message pattern describing the error
 *  \param[in] args values for p
 */
typedef void (axa_walk_error_t)(void *ctxt, const char *p, va_list args);


/**
 *  Callback function for an IP address found while walking over
 *  a DNS packet or rdata.
 *
 *  \param[in] ctxt caller's context
 *  \param[in] ip found IP address
 *  \param[in] ip_len length of IP and so either 4 or 16
 *  \param[in] sec name of the DNS section where the IP address was found
 *
 *  \retval true continue walking
 *  \retval false stop walking or parsing after an error
 *	or because a filtering decision has been made
 */
typedef bool (axa_walk_ip_t)(void *ctxt,
			     const axa_walkb_t *ip, size_t ip_len,
			     axa_walks_t *sec);

/**
 *  Callback function for a domain found while walking over
 *  a DNS packet or rdata.
 *
 *  \param[in] ctxt caller's context
 *  \param[in] name found domain in wire format
 *  \param[in] name_len length of name
 *  \param[in] dtype context in which name was found
 *  \param[in] rtype rtype of owned or containing rdata
 *  \param[in] sec name of the DNS section where the domain was found
 *
 *  \retval true continue walking
 *  \retval false stop walking or parsing after an error
 *	or because a filtering decision has been made
 */
typedef bool (axa_walk_domain_t)(void *ctxt,
				 axa_walkb_t *name, size_t name_len,
				 axa_walk_dom_t dtype,
				 uint rtype, axa_walks_t *sec);

/**
 *  Examine or walk over an owner name and its rdata.
 *
 *  \param[in] ctxt caller's context
 *  \param[in] ops list of callback functions
 *  \param[in] oname owner name if known or NULL if unknown
 *  \param[in] oname_len length of owner name
 *  \param[in] pkt_base start of DNS packet or NULL for isolated rdata
 *  \param[in] pkt_lim end + 1 of DNS packet or end of rdata+1
 *  \param[in] rdata resource data or rdata to walk or examine
 *  \param[in] rdlength rdata length
 *  \param[in] rtype resource type or rtype of rdata
 *  \param[in] sec section name
 *
 *  \retval true continue walking
 *  \retval false stop walking or parsing after an error
 *	or because a filtering decision has been made
 */
typedef bool (axa_walk_rdata_t)(void *ctxt, axa_walk_ops_t *ops,
				axa_walkb_t *oname, size_t oname_len,
				axa_walkb_t *pkt_base,
				axa_walkb_t *pkt_lim,
				axa_walkb_t *rdata,
				size_t rdlength,
				uint rtype,
				axa_walks_t *sec);

/** List of DNS callback Functions */
struct axa_walk_ops {
	axa_walk_error_t	*error;     /**< walk_error() */
	axa_walk_ip_t		*ip;	    /**< walk_ip() */
	axa_walk_domain_t	*domain;    /**< walk_domain() */
	axa_walk_rdata_t	*rdata;     /**< walk_rdata() */
};

/**
 *  Generic rdata callback that calls axa_walk_ops_t->error, ->ip, or ->domain
 *  as it walks over rdata.  This function can be used in axa_walk_ops_t
 *  explicitly or by setting axa_walk_ops_t->rdata==NULL or called by
 *  the function specified in axa_walk_ops_t->rdata.  That is useful when
 *  external criteria determine whether an rdata field should be examined
 *  or skipped.
 */
extern axa_walk_rdata_t axa_walk_rdata;

/**
 *  Generic callback to skip rdata for uses that do not care about an
 *  rdata field.
 */
extern axa_walk_rdata_t axa_skip_rdata;

/**
 *  Walk over or examine a DNS packet.
 *
 *  \param[in] ctxt caller's context given callback functions
 *  \param[in] ops list of callback functions
 *  \param[in] pkt_base start of the DNS packet
 *  \param[in] pkt_len length of the DNS packet
 */
extern void axa_walk_dns(void *ctxt, axa_walk_ops_t *ops,
			 axa_walkb_t *pkt_base, size_t pkt_len);

/**@}*/

#endif /* AXA_DNS_WALK_H */
