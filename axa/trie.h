/*
 * Tries for SRA servers and RAD modules
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

#include <axa/bits.h>
#include <axa/protocol.h>


typedef uint32_t tval_t;
typedef uint16_t tval_idx_t;

/* Values in trie nodes for servers. */
#define TVAL_IDX_BITS		16
#define TVAL_IDX_MASK		((1<<TVAL_IDX_BITS) - 1)
#define TVAL_TO_OUTPUT_IDX(tval) ((tval) & TVAL_IDX_MASK)
#define TVAL_TO_TAG(tval)	((tval) >> TVAL_IDX_BITS)

#define TAG_ID_TO_TVAL(t, i) (tval_t)((((axa_tag_t )(t)) << TVAL_IDX_BITS)  \
				      | (((tval_idx_t)(i)) & TVAL_IDX_MASK))


/* The list of values for a trie node. */
typedef struct tval_list tval_list_t;
struct tval_list {
	tval_list_t	*free;
	uint16_t	len;
	uint16_t	in_use;
	tval_t		tvals[0];
};


/* A value for a key found in the trie and hints about the source
 * of the data that matched the key. */
typedef struct hit {
	tval_t		tval;
	axa_nmsg_idx_t	field_idx;
	axa_nmsg_idx_t	val_idx;
} hit_t;
typedef struct {
	int		len;
	int		in_use;
	hit_t		hits[0];
} hitlist_t;



typedef enum {
	TRIE_IPV4,
	TRIE_IPV6,
	TRIE_DOM
} trie_type_t;
#define MAX_TRIE_IPV4_PREFIX	64
#define MAX_TRIE_IPV6_PREFIX	128
typedef uint16_t	trie_bitlen_t;
#define BITS_TO_TRIE_KEYLEN(b)	(BITS_TO_AXA_WORDS(b)*sizeof(axa_word_t))
typedef union {
	axa_word_t	w[BYTES_TO_AXA_WORDS(sizeof(axa_p_watch_pat_t))];
	struct in_addr	addr[MAX_TRIE_IPV4_PREFIX/32];
	struct in6_addr	addr6;
	uint8_t		b[1];
} trie_key_t;

typedef struct trie_node trie_node_t;
struct trie_node {
	trie_node_t	*parent;
	trie_node_t	*child[2];
	tval_list_t	*exact;
	tval_list_t	*wild;
	axa_ref_cnt_t	ref_cnt;
	trie_bitlen_t	bitlen;
	trie_key_t	key;
};

typedef struct {
	trie_node_t	*ipv4_root;	/* The roots of the three tries */
	trie_node_t	*ipv6_root;
	trie_node_t	*dom_root;

	/* A hit list cannot be bigger. */
	int		hitlist_max;

	/* Arrange to delete a trie node.
	 * The node must have no children and no parent. */
	void		(*node_delete)(trie_node_t *node);

	/* Arrange to delete a list of values that once belonged to a node. */
	void		(*tval_list_delete)(tval_list_t *tval_list);

	/* get index of previous 'hit' on a node value or -1. */
	bool		(*hitlist_find)(const hitlist_t *hitlist, tval_t tval);

	/* Some changes to the trie must be protected. */
	void		(*lock)(void);
	void		(*unlock)(void);
	void		(*assert_lock)(void);
} trie_roots_t;


extern bool axa_tval_delete(trie_roots_t *roots, tval_list_t **tval_listp,
			    tval_t val);
extern void axa_tval_add(trie_roots_t *roots, tval_list_t **tval_listp,
			 tval_t new, uint padded_len, bool lock_free);
extern size_t axa_trie_to_watch(axa_p_watch_t *w, const trie_node_t *trie,
				trie_type_t trie_type, bool is_wild);
extern void axa_trie_node_free(trie_node_t *node);
extern void axa_trie_node_delete(trie_roots_t *roots, trie_type_t trie_type,
				 trie_node_t *node, bool is_wild, tval_t tval);
extern bool axa_trie_watch_add(axa_emsg_t *emsg, trie_roots_t *roots,
			       trie_node_t **node, const axa_p_watch_t *watch,
			       size_t watch_len, tval_t tval);
extern void axa_trie_search_su(trie_roots_t *roots, const axa_socku_t *su,
			       hitlist_t **hitlistp,
			       axa_nmsg_idx_t field_idx,
			       axa_nmsg_idx_t val_idx);
extern bool axa_trie_search_dom(axa_emsg_t *emsg, trie_roots_t *roots,
				const uint8_t *name, uint name_len,
				hitlist_t **hitlistp,
				axa_nmsg_idx_t field_idx,
				axa_nmsg_idx_t val_idx);
extern void axa_tries_free(trie_roots_t *roots);
extern void axa_hitlist_append(const trie_roots_t *roots,
			       hitlist_t **hitlistp,
			       const tval_list_t *tval_list,
			       axa_nmsg_idx_t field_idx,
			       axa_nmsg_idx_t val_idx);

#endif /* AXA_TRIE_H */
