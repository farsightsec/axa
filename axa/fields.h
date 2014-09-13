/*
 * Advanced Exchange Access (AXA) nmsg definitions
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

#ifndef AXA_FIELDS_H
#define AXA_FIELDS_H

/*! \file fields.h
 *  \brief Nmsg definitions for libaxa
 *
 *  This file contains nmsg field related datatype definitions and function 
 *  declarations.
 */


#include <nmsg/timespec.h>		/* for OS X */
#include <nmsg.h>

#include <axa/protocol.h>
#include <axa/axa.h>


/* nmsg field contents */
typedef enum {
	AXA_FC_UNKNOWN,			/* do not care about this field */
	AXA_FC_IP_DGRAM,		/* IP datagram */
	AXA_FC_IP,			/* binary IP address */
	AXA_FC_IP_ASCII,		/* ASCII IP address */
	AXA_FC_DOM,			/* wire-format domain */
	AXA_FC_DOM_ASCII,		/* ASCII domain */
	AXA_FC_HOST,			/* ASCII domain or IP address */
	AXA_FC_RDATA,			/* DNS rdata */
	AXA_FC_DNS,			/* complete DNS packet */
	AXA_FC_JSON,
} axa_fc_t;

/* A sub-field such as a JSON tag */
typedef struct axa_nmsg_sf {
	struct axa_nmsg_sf *next;
	axa_fc_t	fc;
	size_t		len;
	char		name[0];
} axa_nmsg_sf_t;

typedef struct vm_entry vm_entry_t;

/* nmsg fields worth parsing */
#define AXA_FIELD_NM_LEN    32
typedef struct {
	axa_nmsg_idx_t	idx;
} axa_nmsg_help_t;
typedef struct axa_nmsg_field {
	struct axa_nmsg_field *next;
	char  vname[AXA_FIELD_NM_LEN];	/* message module vendor name */
	char  mname[AXA_FIELD_NM_LEN];	/* message type as a string */
	char  name[AXA_FIELD_NM_LEN];	/* name of this field */
	axa_nmsg_sf_t	*sf;		/* list of sub-fields */
	axa_nmsg_idx_t	idx;		/* nmsg field index */
	axa_nmsg_help_t	class;
	axa_nmsg_help_t	rtype;
	axa_nmsg_help_t	owner;
	axa_nmsg_help_t	enm;
	uint		enm_val;	/* target enum value */
	axa_fc_t	fc;
	vm_entry_t	*vm;
	uint		line_num;
} axa_nmsg_field_t;

#define AXA_HELPER_CACHE_LEN 4
typedef struct {
	uint		len;
	struct {
		axa_nmsg_idx_t	idx;
		axa_nmsg_idx_t	val_idx;
		uint		val;
	} e[AXA_HELPER_CACHE_LEN];
} axa_helper_cache_t;


/* fields.c */
extern bool axa_get_helper(axa_emsg_t *emsg, const nmsg_message_t msg,
			   const axa_nmsg_help_t *help, axa_nmsg_idx_t val_idx,
			   void *val, size_t *val_len,
			   size_t min_val_len, size_t max_val_len,
			   axa_helper_cache_t *cache);
extern const axa_nmsg_field_t axa_null_field;
extern const axa_nmsg_field_t *axa_msg_fields(const nmsg_message_t msg);
extern void axa_unload_fields(void);
/**
 *  read the nmsg fields file to build the tables of known vendor IDs, message
 *  types, and fields
 *  \param fields_file const char * canonical name of nmsg fields file
 */
extern void axa_load_fields(const char *fields_file);


/* get_field_name.c */
extern const char *axa_get_field_name(const nmsg_message_t msg,
				      unsigned field_idx);

/* wdns_res.c
 * buf is used only for bogus wres */
#define AXA_WDNS_RES_STRLEN 24
extern const char *axa_wdns_res(unsigned int wres, char *buf, size_t buf_len);

/* wdns_rtype.c */
extern const char *axa_rtype_to_str(char *buf, size_t buf_len,
				    unsigned int rtype);

/* nmsg_serialize.c */
extern nmsg_res axa_nmsg_serialize(axa_emsg_t *emsg, nmsg_message_t msg,
				   uint8_t **pbuf, size_t *buf_len);

/* whit2msg.c */
/**
 *  Create an nmsg from a watch hit
 *  \param[out] emsg if something goes wrong, this will contain the reason
 *  \param[in] nmsg_input nmsg_input_t
 *  \param[in] msgp nmsg_message_t pointer the nmsg will
 *  \param[in] whit axa_p_whit_t pointer
 *  \param[in] whit_len size_t length of whit
 *
 *  \return true on success, false on failure
 */
extern bool axa_whit2nmsg(axa_emsg_t *emsg, nmsg_input_t nmsg_input,
			  nmsg_message_t *msgp,
			  axa_p_whit_t *whit, size_t whit_len);


#endif /* AXA_FIELDS_H */
