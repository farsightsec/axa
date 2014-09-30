/*
 * Advanced Exchange Access (AXA) tries for SRA servers and RAD modules
 *
 *	The trie code is in the server library and so in radd and so available
 *	to RAD modules.
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

#ifndef AXA_TRIE_H
#define AXA_TRIE_H

/*! \file trie.h
 *  \brief Top-level interface specification for libaxa
 *
 * This file contains AXA trie or patricia tree macros, datatype definitions
 * and function declarations.
 *
 * These trie functions use patricia trees to recognize IP addresses and
 * DNS domain names.  IP address CIDR blocks or domains, each with a
 * 32-bit value, are added to, looked up in, and deleted from trees.
 * The result of a look-up is an array of 0 or more "hits" or values.
 * Look-ups or reading is done without any locking, except
 * periodically when the readers signal their disinterest in old data.
 *
 * A successful look-up produces an array of hits for each of the matching
 * CIDR blocks or domains.  For example, lookup up "test.example.com"
 * might yield an array consisting of all of the values for the
 * "test.example.com" and "com" nodes in the trie.
 *
 * IPv4, IPv6, and domain names are.maintained internally in separate three
 * tries that can be viewed as a single trie from the outside.
 */

#include <axa/bits.h>
#include <axa/protocol.h>


typedef uint32_t tval_t;		/**< A value at a trie node */

/**@{*/
/** Pack and unpack trie node value into a pair of values such as an
 * SRA client ID and an nmsg index
 */
typedef uint16_t tval_idx_t;
#define TVAL_IDX_BITS		16
#define TVAL_IDX_MASK		((1<<TVAL_IDX_BITS) - 1)
#define TVAL_TO_OUTPUT_IDX(tval) ((tval) & TVAL_IDX_MASK)
#define TVAL_TO_TAG(tval)	((tval) >> TVAL_IDX_BITS)

#define TAG_ID_TO_TVAL(t, i) (tval_t)((((axa_tag_t )(t)) << TVAL_IDX_BITS)  \
				      | (((tval_idx_t)(i)) & TVAL_IDX_MASK))

/**@}*/

/** An array of values for a trie node. */
typedef struct tval_list tval_list_t;
struct tval_list {
	tval_list_t	*free;		/**< chain while awaiting destruction */
	uint16_t	len;		/**< Total length of the array */
	uint16_t	in_use;		/**< Number of valid values */
	tval_t		tvals[0];	/**< The values for the trie node */
};


/** A single value for a key found in the trie and hints about the source
 * of the data that matched the key. */
typedef struct hit {
	tval_t		tval;		/**< Value for the key in the trie. */
	axa_nmsg_idx_t	field_idx;	/**< nmsg field index from caller */
	axa_nmsg_idx_t	val_idx;	/**< nmsg value index from caller */
} hit_t;

/** The successful result of looking up a key is an array of "hits" */
typedef struct {
	int		len;		/**< Total length of the array */
	int		in_use;		/**< Number of valid "hits" */
	hit_t		hits[0];	/**< The hits */
} hitlist_t;


typedef struct trie_node trie_node_t;	/**< a trie node */

/** Each externally visible trie consists of one each of these internal types. */
typedef enum {
	TRIE_IPV4,			/**< IPv4 addresses */
	TRIE_IPV6,			/**< IPv6 addresses */
	TRIE_DOM			/**< DNS domains */
} trie_type_t;

#define MAX_TRIE_IPV4_PREFIX	64	/**< IPv4 keys are one 64-bit word */
#define MAX_TRIE_IPV6_PREFIX	128	/**< IPv6 keys are two words */
typedef uint16_t	trie_bitlen_t;	/**< valid bits in a trie key */
/** @cond */
#define BITS_TO_TRIE_KEYLEN(b)	(BITS_TO_AXA_WORDS(b)*sizeof(axa_word_t))
/** @endcond */
/** A trie key. */
typedef union {
	/** One or more 64-bit words */
	axa_word_t	w[BYTES_TO_AXA_WORDS(sizeof(axa_p_watch_pat_t))];
	/** One 64-bit word for an IPv4 address */
	struct in_addr	addr[MAX_TRIE_IPV4_PREFIX/32];
	/** Two 64-bit words for an IPv6 address */
	struct in6_addr	addr6;
	/** Bytes rounded-up to words for a domain */
	uint8_t		b[1];
} trie_key_t;

/**
 * The shape of a trie node does not matter except to the trie code and
 * to trie users that manage lists of obsolete nodes for lock-free searching.
 * Those users must examine, change or use only .parent for linking
 * their lists of dead nodes.
 */
struct trie_node {
	trie_node_t	*parent;	/**< free list or live parent */
	trie_node_t	*child[2];	/**< children of this node */
	tval_list_t	*exact;		/**< exact match values or 'hits' */
	tval_list_t	*wild;		/**< CIDR or DNS wildcard hits */
	trie_bitlen_t	bitlen;		/**< number of bits in the key */
	trie_key_t	key;		/**< key */
};

/**
 * This is the handle on an AXA trie.  Trie users must create and initialize
 * one of these structures before first using an AXA trie.  Zero or NULL
 * is acceptable for all of its entries.
 */
typedef struct {
	trie_node_t	*ipv4_root;	/**< root of the internal IPv4 trie */
	trie_node_t	*ipv6_root;	/**< root of the internal IPv6 trie */
	trie_node_t	*dom_root;	/**< root of the domain name trie */

	int		hitlist_max;	/**< hit array limit; default 10 */

	/**
	 * Delete or schedule the deletion of a trie node.
	 * AXA trie users that do not need non-blocking trie searches can
	 * set this to NULL or axa_trie_node_delete.  A supplied function must
	 * eventually call axa_trie_node_free().
	 */
	void		(*node_free)(trie_node_t *node);

	/**
	 * Delete or schedule the deletion of an array of values that once
	 * belonged to a trie node.
	 * AXA trie users that do not need non-blocking trie searches can
	 * set this to NULL or axa_trie_node_delete.  A supplied function must
	 * eventually call free().
	 */
	void		(*tval_list_free)(tval_list_t *tval_list);

	/**
	 * NULL or return -1 or the index of an identical, previously
	 * found 'hit' on a node value
	 */
	bool		(*hitlist_find)(const hitlist_t *hitlist, tval_t tval);

	/* Some changes to the trie must be protected. */
	void		(*lock)(void);	/**< Lock to add or delete a node */
	void		(*unlock)(void);    /**< Unlock the trie */
	void		(*assert_lock)(void);	/**< Check the trie lock */
} trie_roots_t;


/**
 * Delete a value from an array of trie node values.
 *
 * \param[in] roots handle on the trie.
 * \param[in] tval_listp pointer to array from which the value should be removed
 * \param[in] val remove the first instance of this value if present
 *
 * \retval true if an instance of the value was found and removed
 * \retval false if an instance of the value was not found
 */
extern bool axa_tval_delete(trie_roots_t *roots, tval_list_t **tval_listp,
			    tval_t val);

/**
 * Add a value to an array of values
 *
 * \param[in] roots handle on the trie.
 * \param[in] tval_listp pointer to array to which the value should be added
 * \param[in] new value to add
 * \param[in] padded_len 0 or new length of the array including optional
 *		padding for future additions
 * \param[in] lock_free true if lock-free searching is supported by the trie.
 */
extern void axa_tval_add(trie_roots_t *roots, tval_list_t **tval_listp,
			 tval_t new, uint padded_len, bool lock_free);

/**
 * Convert the key in a trie node to an AXA watch.
 *
 * \param[out] w existing watch that will be filled.
 * \param[in] node convert the key in this AXA trie node
 * \param[in] node_type TRIE_IPV4, TRIE_IPV6, or TRIE_DOM
 * \param[in] is_wild true if the resulting watch should be for an IP address
 *		CIDR block or a DNS wild card
 *
 * \return overall size of the watch
 */
extern size_t axa_trie_to_watch(axa_p_watch_t *w, const trie_node_t *node,
				trie_type_t node_type, bool is_wild);

/**
 * Free a trie node including its arrays of values.  The node must have
 * already been deleted from the trie.
 *
 * \param[in] node to be destroyed
 */
extern void axa_trie_node_free(trie_node_t *node);

/**
 * Remove a value from an AXA trie node and then delete the node from
 * the trie if it is empty.
 *
 * \param[in] roots handle on the trie
 * \param[in] trie_type TRIE_IPV4, TRIE_IPV6, or TRIE_DOM
 * \param[in] node to be changed
 * \param[in] is_wild true if the value is for a CIDR block or DNS wild card
 * \param[in] tval value to be removed
 */
extern void axa_trie_node_delete(trie_roots_t *roots, trie_type_t trie_type,
				 trie_node_t *node, bool is_wild, tval_t tval);

/**
 * Add a watch to an AXA trie.
 * Create a node with a key derived from the watch if the node
 * does not already exist and then add value to the node.
 *
 * \param[out] emsg will contain the reason for a false result.
 * \param[in] roots handle on the trie
 * \param[out] node will point to the node if not NULL.
 * \param[in] watch provides the IP address or domain name for the key
 * \param[in] watch_len is the length of the watch.  It is usually
 *	   less than sizeof(axa_p_watch_t) because maximum sized domain names
 *	   are rare.
 * \param[in] tval is the value that will be added to either the "wild" or
 *	    "exact" array of values in the node.
 *
 * \retval true if no errors were encountered.  Node will be set if not NULL
 * \retval false error was was encountered and emsg will contain the reason
 */
extern bool axa_trie_watch_add(axa_emsg_t *emsg, trie_roots_t *roots,
			       trie_node_t **node, const axa_p_watch_t *watch,
			       size_t watch_len, tval_t tval);

/**
 * Search an AXA trie for an IP address
 *
 * \param[in] roots handle on the trie
 * \param[in] su points to an axa_socku_t union containing the IP address
 * \param[in,out] hitlistp the array of values in found trie nodes is appended to
 *		this array.  It is created if *hitlistp is NULL and a value
 *		is found.  More than one trie node can contribute values;
 *		for example a search for 10.2.3.4 can match nodes with
 *		keys 10.0.0.0/8, 10.2.0.0/16, and 10.2.3.4.
 * \param[in] field_idx is associated with each value added to the hitlistp array
 *		to let the caller remember which nmsg value caused each "hit"
 * \param[in] val_idx is associated with each value added to the hitlistp array
 */
extern void axa_trie_search_su(trie_roots_t *roots, const axa_socku_t *su,
			       hitlist_t **hitlistp,
			       axa_nmsg_idx_t field_idx,
			       axa_nmsg_idx_t val_idx);

/**
 * Search an AXA trie for a DNS domain.
 *
 * \param[out] emsg will contain the reason for a false result.
 * \param[in] roots handle on the trie
 * \param[in] name points to the domain in wire format
 * \param[in] name_len is the length of the domain
 * \param[in,out] hitlistp The array of values in found trie nodes is appended to
 *		this array.  It is created if *hitlistp is NULL and a value
 *		is found.  More than one trie node can contribute values;
 *		for example a search for www.example.com can match nodes with
 *		keys www.example.com and *.com.
 * \param[in] field_idx is associated with each value added to the hit list
 *		to let the caller remember which nmsg value caused each "hit"
 * \param[in] val_idx is associated with each value added to the hitlistp array
 *
 * \retval true if no errors were encountered.
 * \retval false error such as a bad domain namewas was encountered.
 *		emsg will contain the reason.
 */
extern bool axa_trie_search_dom(axa_emsg_t *emsg, trie_roots_t *roots,
				const uint8_t *name, uint name_len,
				hitlist_t **hitlistp,
				axa_nmsg_idx_t field_idx,
				axa_nmsg_idx_t val_idx);

/**
 * Free an AXA trie.
 *
 * \param[in] roots handle on the trie to be destroyed.
 */
extern void axa_tries_free(trie_roots_t *roots);

/**
 * Append an array of values such as from a trie node to a "hit list"
 *
 * \param[in] roots handle on the trie
 * \param[in,out] hitlistp is the "hit list" array to which the value list
 *		will be added.
 * \param[in] tval_list is the list of values
 * \param[in] field_idx is associated with each value added to the hit list
 *		to let the caller remember which nmsg value caused each "hit".
 * \param[in] val_idx is associated with each value added to the hitlistp array
 */
extern void axa_hitlist_append(const trie_roots_t *roots,
			       hitlist_t **hitlistp,
			       const tval_list_t *tval_list,
			       axa_nmsg_idx_t field_idx,
			       axa_nmsg_idx_t val_idx);

#endif /* AXA_TRIE_H */
