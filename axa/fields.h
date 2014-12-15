/*
 * Advanced Exchange Access (AXA) nmsg definitions
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


/** nmsg field contents type */
typedef enum {
	AXA_FC_UNKNOWN,			/**< ignore this field */
	AXA_FC_IP_DGRAM,		/**< IP datagram */
	AXA_FC_IP,			/**< binary IP address */
	AXA_FC_IP_ASCII,		/**< ASCII IP address */
	AXA_FC_DOM,			/**< wire-format domain */
	AXA_FC_DOM_ASCII,		/**< ASCII domain */
	AXA_FC_HOST,			/**< ASCII domain or IP address */
	AXA_FC_RDATA,			/**< DNS rdata */
	AXA_FC_DNS,			/**< complete DNS packet */
	AXA_FC_JSON,			/**< JSON encoded */
} axa_fc_t;

/** Some some fields of some nmsg messages have a type/value structure such
 *  as JSON tags. */
typedef struct axa_nmsg_sf {
	struct axa_nmsg_sf *next;	/**< next sub-field of nmsg field */
	axa_fc_t	fc;		/**< sub-field content type */
	size_t		len;		/**< length of sub-field name */
	char		name[0];	/**< name of this sub-field */
} axa_nmsg_sf_t;

/** nmsg vendor IDs and message types worthy decoding by SRA
 *  Each (vendor,message type) pair has a list of fields that
 *  contain domains or IP addresses. */
typedef struct vm_entry vm_entry_t;

/** maximum length of an AXA field name */
#define AXA_FIELD_NM_LEN    32

/** An auxilary value such as DNS class or rtype */
typedef struct {
	axa_nmsg_idx_t	idx;		/**< big enough for nmsg field index */
} axa_nmsg_help_t;

/** An nmsg message understood by AXA.
 *  Every interesting field in an interesting nmsg message is
 *  defined by a line in the fields file.  Each line is compiled into a list
 *  of these structures, one for each interesting nmsg field.
 *  Some nmsg fields need the contents of other nmsg fields for proper decoding,
 *  such as DNS class and rtype for DNS rdata.
 *  Some nmsg fields have varying types, such as JSON or other values.
 *  When .enm is not AXA_NMSG_IDX_NONE, then one of these applies only
 *  to messages where contents of the nmsg field with the index in .enm
 *  is equal to .enm_val */
typedef struct axa_nmsg_field {
	struct axa_nmsg_field *next;    /**< next interesting field */
	char  vname[AXA_FIELD_NM_LEN];	/**< nmsg module vendor name */
	char  mname[AXA_FIELD_NM_LEN];	/**< nmsg type such as "dnsqr" */
	char  name[AXA_FIELD_NM_LEN];	/**< nmsg field name such as "qname" */
	axa_nmsg_sf_t	*sf;		/**< optional list of sub-fields */
	axa_nmsg_idx_t	idx;		/**< nmsg field index */
	axa_nmsg_help_t	class;		/**< optional nmsg index of DNS class */
	axa_nmsg_help_t	rtype;		/**< optional nmsg index of DNS rtype */
	axa_nmsg_help_t	owner;		/**< optional index rdata owner */
	axa_nmsg_help_t	enm;		/**< nmsg index of nmsg 'enum' field */
	uint		enm_val;	/**< target nmsg enum field value */
	axa_fc_t	fc;		/**< nmsg field content type */
	vm_entry_t	*vm;		/**< parent nmsg vid & msgtype */
	uint		line_num;	/**< line number in config file */
} axa_nmsg_field_t;

/** AXA helper cache size
 *  A single nmsg message can have more than two or more fields involving
 *  the same helper values.  For example, an nmsg message containing a
 *  DNS response message with domain and rdata fields can depend on a single
 *  field containing the DNS class.
 *  Helper caches are automatic variables in a caller's stack. */
#define AXA_HELPER_CACHE_LEN 4

/** AXA helper cache */
typedef struct {
	uint		len;		/**< number of valid cache entries */
	struct {
	    axa_nmsg_idx_t  idx;	/**< nmsg field index */
	    axa_nmsg_idx_t  val_idx;    /**< nmsg val index */
	    uint	    val;	/**< contents of the nmsg field */
	} e[AXA_HELPER_CACHE_LEN];      /**< array of cache entries */
} axa_helper_cache_t;


/* fields.c */
/**
 *  Get the contents of a "helper" field for a fields file line
 *
 *  \param[out] emsg if something goes wrong, this will contain the reason
 *  \param[in] msg the nmsg to query
 *  \param[in] help nmsg helper
 *  \param[in] val_idx value index
 *  \param[out] val the value will be stored here
 *  \param[out] val_len optional length of value, can be NULL for fixed value
 *	length
 *  \param[in] min_val_len minimum allowed data length
 *  \param[in] max_val_len maximum allowed data length
 *  \param[in,out] cache optional cache pointer to expedite repeated fetches
 *
 *  \retval true successful lookup, val and val_len are set
 *  \retval false something went wrong, check emsg
 */
extern bool axa_get_helper(axa_emsg_t *emsg, const nmsg_message_t msg,
			   const axa_nmsg_help_t *help, axa_nmsg_idx_t val_idx,
			   void *val, size_t *val_len,
			   size_t min_val_len, size_t max_val_len,
			   axa_helper_cache_t *cache);

/** An empty field definition used as a template or a placeholder */
extern const axa_nmsg_field_t axa_null_field;

/**
 *  Check the global vid/msgtype hash table to see if we know a vendor ID and
 *  message type and if so, get our list of its interesting fields.
 *
 *  \param[in] msg nmsg message to query
 *
 *  \return success: pointer to axa_nmsg_field_t containing the nmsg vid and
 *  msgtype, failure: NULL
 */
extern const axa_nmsg_field_t *axa_msg_fields(const nmsg_message_t msg);

/**
 *  Unload all data from the global vid/msgtype hash table and free all
 *  memory.
 */
extern void axa_unload_fields(void);

/**
 *  Read the nmsg fields file to build the tables of known vendor IDs, message
 *  types, and fields.
 *
 *  \param[in] fields_file const char * canonical name of nmsg fields file
 */
extern void axa_load_fields(const char *fields_file);


/* get_field_name.c */
/**
 *  Get the name of a field specified by index. Function is a wrapper for
 *  nmsg_message_get_field_name() that returns the string "???" if field name
 *  is not known.
 *
 *  \param[in] msg nmsg to query
 *  \param[in] field_idx field index
 *
 *  \returns success; the name of the field, failure: the string "???"
 */
extern const char *axa_get_field_name(const nmsg_message_t msg,
				      unsigned field_idx);

/** buf is used only for bogus wres */
#define AXA_WDNS_RES_STRLEN 24

/* wdns_res.c */
/**
 *  Lookup wdns result code and return a canonical string representation.
 *  Return a value that can be used as an arg to printf()
 *
 *  \param[in] wres wdns result code
 *  \param[out] buf buffer to hold string representation
 *  \param[out] buf_len length of buffer
 *
 *  \returns the contents of buf
 */
extern const char *axa_wdns_res(unsigned int wres, char *buf, size_t buf_len);

/* wdns_rtype.c */
/**
 *  Lookup wdns rrtype and return a canonical string representation.
 *  Wraps wdns_rrtype_to_str().
 *
 *  \param[out] buf buffer to hold string representation
 *  \param[out] buf_len length of buffer
 *  \param[in] rtype the wdns rrtype code
 *
 *  \returns the contents of buf
 */
extern const char *axa_rtype_to_str(char *buf, size_t buf_len,
				    unsigned int rtype);

/* whit2msg.c */
/**
 *  Create an nmsg from a watch hit
 *
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
