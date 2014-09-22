/*
 * Advanced Exchange Access (AXA) Realtime Anomaly Detector (RAD) modules
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

#ifndef RAD_MOD_H
#define RAD_MOD_H

/*! \file rad_mod.h
 *  \brief AXA RAD data types and function declarations.
 *
 *  This file contains the RAD data types and function declarations for a
 *  RAD module.  Before including this file,
 *  \#define RAD_MOD_PREFIX xxx
 *  where "xxx" is the name of the module to declare
 *  axa_rad_\#\#prefix\#\#_open() axa_rad_\#\#prefix\#\#_whit(),
 *  and axa_rad_\#\#prefix\#\#_close().
 *
 *  A RAD module expects the RAD daemon to enable SRA channels and
 *  start SRA watches based on a list of axa_rad_parm_t parameters that
 *  the module has computed from an optional list of watches and channels
 *  as well as optional strings from the users file and the RAD client.
 *  The RAD daemon delivers AXA messages containing nmsg or SIE messages and
 *  dark channel packets matching those watches to the RAD module.  The module
 *  tells the RAD daemon to send copies of the AXA messages that the module
 *  considers anomalous to the RAD client.
 */

#include <axa/wire.h>

/**
 *  A single RAD parameter specifying an SRA channel to enable or watch to
 *  start in the form of an AXA message header and body.
 *  Only hdr.len and hdr.op are valid in the header.  hdr.len is in
 *  host byte-order but body is in wire format.
 */
typedef struct {
	axa_p_hdr_t	hdr;		/**< axa protocol header */
	axa_p_body_t	body;		/**< variable size AXA message body */
} axa_rad_p_t;

/**
 *  A member of a linked list RAD module parameters.
 */
typedef struct axa_rad_parm axa_rad_parm_t;
struct axa_rad_parm {
	axa_rad_parm_t	*fwd;		/**< next item in list */
	axa_rad_p_t	p;		/**< RAD struct */
};


/**
 *  Open a RAD module.
 *	All of these functions can be called concurrently by two or more
 *	RAD server threads and so must protect their data.
 *	A module's close function will be called by the RAD daemon if its
 *	open() function returns a non-null ctxt even if the open() function
 *	fails.
 *
 *	\param[out] ctxt a non-null context for this instance of the module
 *	    that must be freed by the module in its close() function.
 *	\param[out] errmsg NULL on success but on failure, an error message that
 *	    must be freed by the caller.
 *	\param[in] out_parms a list of 0 or more axa_rad_parm_t parameters
 *	    consisting of AXA channel and watch enable commands usually
 *	    generated by the module from in_parms, uparms, and cparms.
 *	    It is usually a dynamically allocated list owned by the module
 *	    and freed by the module's close() function.
 *	\param[in] in_parms a linked list of axa_rad_parm_t parameters
 *	    consisting of the AXA watches specified by the RAD client with
 *	    AXA messages before the AXA_P_OP_ANOM message.
 *	    These watches are given to all anomaly modules with the same tag.
 *	\param[in] uparms an ASCII string of parameters from the users file.
 *	    invalid after the open function returns.
 *	\param[in] cparms an ASCII string of parameters from the RAD client.
 *	    invalid after the open function returns.
 *
 *	\retval true, success
 *	\retval false, failure
 */
typedef bool (axa_rad_open_t)(void **ctxt, char **errmsg,
			      const axa_rad_parm_t **out_parms,
			      const axa_rad_parm_t *in_parms,
			      const char *uparms, const char *cparms);

/**
 *  RAD module watch hit.
 *  Say whether to forward an AXA watch "hit" to the RAD client.
 *
 *	\param[in] ctxt context for this instance of the module
 *	\param[in] errmsg NULL except after an error return when it contains an
 *	    string explaining the error and that must be freed by the caller.
 *	\param[in] whit watch "hit" containing an SIE nmsg message or dark
 *	    channel that matched one of watches specified by the module when it
 *	    was opened.
 *	\param[in] whit_len the length of whit
 *	\param[in] msg nmsg message from whit decoded by axa_whit2nmsg if
 *	    whit->hdr.type==AXA_P_WHIT_NMSG
 *	\param[in] dgp IP packet from whit decoded by nmsg_ipdg_parse_pcap_raw()
 *
 *	\retval -1 error with text in errmsg
 *	\retval 0 no, do not forward whit to the RAD client
 *	\retval 1 yes, forward whit to the RAD client
 */
typedef int (axa_rad_whit_t)(void *ctxt, char **errmsg,
			     const axa_p_whit_t *whit, size_t whit_len,
			     const nmsg_message_t msg,
			     const struct nmsg_ipdg *dgp);

/**
 *  RAD module close
 *  The module should free its context, ctxt, and any other resources
 *  including the list of axa_rad_parm_t parameters given by the module
 *  to the RAD daemon via the out_parms parameter of its open() function.
 *
 *	\param[in] ctxt
 */
typedef void (axa_rad_close_t)(void *ctxt);


/** This string among the parameters for a RAD module in the users file
 *  allows the RAD client to specify parameters for the module when the
 *  client sends its AXA_P_OP_ANOM message. */
#define AXA_RAD_CPARMS_ALLOWED	"+"

/** The names of the three functions exported by a RAD module start with
 * this string/prefix. */
#define RAD_PREFIX "axa_rad_"

#ifdef AXA_RAD_MOD
/* Generate prototypes for a RAD module's exported functions.
 *	AXA_RAD_MOD_OPEN, AXA_RAD_MOD_WHIT, and AXA_RAD_MOD_CLOSE are
 *	defined in Makefile.inc to be the correct function names of the
 *	modules. */
axa_rad_open_t AXA_RAD_MOD_OPEN;
axa_rad_whit_t AXA_RAD_MOD_WHIT;
axa_rad_close_t AXA_RAD_MOD_CLOSE;
#endif


#endif /* RAD_MOD_H */
