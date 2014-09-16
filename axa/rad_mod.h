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

/*! \file protocol.h
 *  \brief AXA RAD datatypes and function declarations.
 *
 *  This file contains the RAD datatypes and function declarations.
 *  Before including this file,
 *  #define RAD_MOD_PREFIX xxx
 *  to declare axa_rad_##prefix##_open() axa_rad_##prefix##_whit(),
 *  and axa_rad_##prefix##_close()
 */

#include <axa/wire.h>

/**
 *  RAD protocol format
 *  AXA protocol header and body. Only hdr.len and hdr.op are valid; hdr.len is
 *  in host byte-order, body is in wire format. 
 */
typedef struct axa_rad_p axa_rad_p_t;
struct axa_rad_p {
	axa_p_hdr_t	hdr;            /**< axa protocol header */
	axa_p_body_t	body;		/**< variable size */
};

/**
 *  RAD parameters
 *  Linked list of axa_rad_p_t structs
 */
typedef struct axa_rad_parm axa_rad_parm_t;
struct axa_rad_parm {
	axa_rad_parm_t	*fwd;       /**< next item in list */
	axa_rad_p_t	p;              /**< RAD struct */
};


/**
 *  All of these functions can be called concurrently by two or more RAD server
 *	threads and so must protect themselves.
 *
 * When it is opened, the module is given
 *	in_parms, a linked list of axa_rad_parm_t,
 *	uparams, an ASCII string of parameters from the users file,
 *	cparms, an ASCII string of parameters from the RAD client.
 *	    *in_parms, *uparms, and *cparms are invalid after the open function
 *	    returns.
 *
 * On a successful return, the module sets
	*ctxt=a non-null context,
 *	*out_parms=list of 0 or more axa_rad_parm_t
 *	If necessary, *ctxt and *out_parms must be freed by the module
 *	    when it is closed.
 * false=fatal error with
 *	*ctxt=NULL,
 *	*out_parms=NULL,
 *	*errmsg=NULL or an error message that will be freed by the caller. 
 *
 *	\param[in] ctxt
 *	\param[in] errmsg
 *	\param[in] out_parms
 *	\param[in] in_parms
 *	\param[in] uparms
 *	\param[in] cparms
 *
 *	\retval true
 *	\retval false
 */
typedef bool (axa_rad_open_t)(void **ctxt, char **errmsg,
			      const axa_rad_parm_t **out_parms,
			      const axa_rad_parm_t *in_parms,
			      const char *uparms, const char *cparms);

/**
 *  RAD watch hit
 *  Say whether to forward a packet to the RAD client.
 *
 *	\param[in] ctxt
 *	\param[in] errmsg
 *	\param[in] whit
 *	\param[in] whit_len
 *	\param[in] msg
 *	\param[in] dgp
 *
 *	\retval -1 error
 *	\retval -0 no
 *	\retval 1 yes
 */
typedef int (axa_rad_whit_t)(void *ctxt, char **errmsg,
			     const axa_p_whit_t *whit, size_t whit_len,
			     const nmsg_message_t msg,
			     const struct nmsg_ipdg *dgp);

/**
 *  RAD close
 *
 *	\param[in] ctxt
 */
typedef void (axa_rad_close_t)(void *ctxt);

/** allow RAD client parameters */
#define AXA_RAD_CPARMS_ALLOWED	"+"

/** RAD prefix string */
#define RAD_PREFIX "axa_rad_"

#ifdef AXA_RAD_MOD
/* Ensure that the exported functions have the right types.
 *	AXA_RAD_MOD_OPEN, AXA_RAD_MOD_WHIT, and AXA_RAD_MOD_CLOSE are
 *	defined in Makefile.inc to be the correct function names of the
 *	modules. */
axa_rad_open_t AXA_RAD_MOD_OPEN;
axa_rad_whit_t AXA_RAD_MOD_WHIT;
axa_rad_close_t AXA_RAD_MOD_CLOSE;
#endif


#endif /* RAD_MOD_H */
