/*
 * Bitwise Tries
 *
 * Used for a radix tree of interesting address blocks and
 * domain names including wildcards.
 *
 * Searches are lock-free.
 * Additions and deletions use a single mutex.  Searchers must occassionally
 * get that lock to reduce their reference counts on old data.
 *
 * IP addresses are kept in host byte order.
 *
 * Domain names are kept in uint64_t words in host bit order and
 * padded with zero bits.
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

#include <axa/axa_endian.h>
#include <axa/trie.h>

#include <stdlib.h>
#include <string.h>


typedef enum {
	TRIE_OP_FOUND,
	TRIE_OP_PARTIAL,
	TRIE_OP_ADDED,
	TRIE_OP_NOT_FOUND
} trie_op_result_t;

static inline trie_node_t **
trie_type_to_root(trie_roots_t *roots, trie_type_t trie_type)
{
	switch (trie_type) {
	case TRIE_IPV4:	return (&roots->ipv4_root);
	case TRIE_IPV6: return (&roots->ipv6_root);
	case TRIE_DOM:	return (&roots->dom_root);
	default:	AXA_FAIL("impossible trie type");
	}
}

#define WILD_TO_TVAL_LISTS(is_wild, node) ((is_wild) ? &(node)->wild	\
					   : &(node)->exact)

#define HAVE_LOCK(_r)	{if ((_r)->assert_lock != NULL) (_r)->assert_lock();}
#define LOCK(_r)	{if ((_r)->lock != NULL) (_r)->lock();}
#define UNLOCK(_r)	{if ((_r)->unlock != NULL) (_r)->unlock();}

/* Remove a value from the list of values that belong to a trie node. */
bool					/* true=found and removed */
axa_tval_delete(trie_roots_t *roots, tval_list_t **tval_listp, tval_t tval)
{
	tval_list_t *tval_list;
	uint n;

	HAVE_LOCK(roots);

	/* Find the tval in the list. */
	tval_list = *tval_listp;
	if (tval_list == NULL)
		return (false);
	for (n = 0; ; ++n) {
		if (n >= tval_list->in_use)
			return (false);
		if (tval_list->tvals[n] == tval)
			break;
	}

	/* Slide the remaining values down
	 * This is safe for concurrent trie searchers that do not lock,
	 * because duplicates are filtered by searchers building their lists,
	 * and because each entry is an aligned 32-bit word. */
	while (n+1 < tval_list->in_use) {
		tval_list->tvals[n] = tval_list->tvals[n+1];
		++n;
	}
	if (--tval_list->in_use == 0) {
		*tval_listp = NULL;
		if (roots->tval_list_free == NULL)
			free(tval_list);
		else
			roots->tval_list_free(tval_list);
	}

	return (true);
}

/* Expand one of the two value lists of a trie node.
 *	lock_free=true if we are working on a value list in an existing trie
 *	    node or other list used by the searchers and so must accomodate
 *	    the lock-free reading by the searchers.
 */
static void
tval_list_expand(trie_roots_t *roots,
		 tval_list_t **tval_listp, size_t new_len, bool lock_free)
{
	tval_list_t *old, *new;
	size_t blen;

	/* Avoid the need for future expansion. */
	new_len += 4;

	blen = sizeof(*new) +  new_len*sizeof(new->tvals[0]);
	new = axa_zalloc(blen);
	new->len = new_len;

	/* finished if expanding a null list. */
	old = *tval_listp;
	if (old == NULL) {
		*tval_listp = new;
		return;
	}
	if (old->in_use != 0) {
		memcpy(new->tvals, old->tvals,
		       sizeof(new->tvals[0])*old->in_use);
		new->in_use = old->in_use;
	}
	if (lock_free) {
		/* Ensure the new list is consistent and then install it. */
		__sync_synchronize();
		*tval_listp = new;

		/* Mark the old list to be freed when all trie searchers
		 * are out of the way. */
		if (roots->tval_list_free == NULL)
			free(old);
		else
			roots->tval_list_free(old);
	} else {
		*tval_listp = new;
		free(old);
	}
}

void
axa_tval_add(trie_roots_t *roots, tval_list_t **tval_listp, tval_t new,
	     uint padded_len, bool lock_free)
{
	tval_list_t *tval_list;

	HAVE_LOCK(roots);

	tval_list = *tval_listp;
	if (tval_list == NULL) {
		if (padded_len < 1)
			padded_len = 1;
		tval_list_expand(roots, tval_listp, padded_len, lock_free);

	} else if (tval_list->in_use >= tval_list->len) {
		AXA_ASSERT(tval_list->in_use == tval_list->len);
		if (padded_len <= tval_list->len)
			padded_len = tval_list->len+1;
		tval_list_expand(roots, tval_listp, padded_len, lock_free);
	}

	tval_list = *tval_listp;

	tval_list->tvals[tval_list->in_use] = new;
	if (lock_free) {
		__sync_synchronize();
	}
	++tval_list->in_use;
}

/* Reverse the labels in a domain name while down-casing. */
static bool				/* false=bad label length */
rev_domain(uint8_t *rev, const uint8_t *name, size_t name_len)
{
	size_t label_len;
	uint8_t *p;

	AXA_ASSERT(name_len > 0 && name_len <= AXA_P_DOMAIN_LEN);
	rev += name_len;
	do {
		label_len = *name++;
		/* quit on a bogus length */
		if (label_len >= name_len || label_len > 0xc0)
			return (false);
		name_len -= label_len+1;
		rev -= label_len+1;
		p = rev;
		*p++ = label_len;
		while (label_len-- > 0)
			*p++ = AXA_TO_LOWER(*name++);
	} while (name_len > 0);

	return (true);
}

static inline axa_word_t
axa_word_mask(uint b)
{
	axa_word_t m;

	m = (axa_word_t)(-1);
	if (b != 0)
		m <<= (AXA_WORD_BITS - b);
	return (m);
}

static bool
dns_to_key(axa_emsg_t *emsg, trie_key_t *key, trie_bitlen_t *prefixp,
	   const uint8_t *name, size_t name_len)
{
	size_t wlen;
	uint n;

	if (name_len == 0 || name_len > AXA_P_DOMAIN_LEN) {
		if (emsg != NULL)
			axa_pemsg(emsg, "bad domain name length=%zd",
				  name_len);
		return (false);
	}
	if (name[name_len-1] != '\0') {
		if (emsg != NULL)
			axa_pemsg(emsg, "domain name not absolute");
		return (false);
	}

	/* Make all of the bytes in the last word well defined. */
	wlen = BYTES_TO_AXA_WORDS(name_len);
	key->w[wlen-1] = 0;

	/* Reverse and convert the domain to a trie key.
	 * Each word in the key must be in native bit order.
	 */
	if (!rev_domain(key->b, name, name_len)) {
		if (emsg != NULL)
			axa_pemsg(emsg, "bad wire format domain label lengths");
		return (false);
	}

	*prefixp = name_len*8;
	AXA_ASSERT(wlen <= AXA_DIM(key->w));
	for (n = 0; n < wlen; ++n)
		key->w[n] = be64toh(key->w[n]);
	return (true);
}

static bool
ck_num(axa_emsg_t *emsg, const char *name, uint val, uint min, uint max)
{
	if (val < min || val > max) {
		axa_pemsg(emsg, "invalid %s of %d", name, val);
		return (false);

	}
	return (true);
}

/* Convert the value in a wire byte-order  watch to trie keys. */
static bool
watch_to_trie_key(axa_emsg_t *emsg, trie_key_t *key,
		  axa_p_watch_type_t type, trie_bitlen_t *prefixp,
		  const axa_p_watch_pat_t *pat, size_t len)
{
	trie_bitlen_t prefix;
	u_int32_t addr_mask;

	AXA_ASSERT(AXA_WORD_BITS == 64);

	memset(key, 0, sizeof(*key));
	prefix = *prefixp;

	switch (type) {
	case AXA_P_WATCH_IPV4:
		if (!ck_num(emsg, "IPv4 address length", len, 1, 4))
			return (false);
		if (!ck_num(emsg, "prefix length", prefix, 1, len*8))
			return (false);
		if (!ck_num(emsg, "address length", len, (prefix+7)/8, 4))
			return (false);
		/* Use 64 bits for IPv4 keys.
		 * Copy 32 bits of IPv4 address to key->addr[0].
		 * Then clear the 32 bits not copied
		 * and the bits beyond the prefix. */
		memcpy(&key->addr[(MAX_TRIE_IPV4_PREFIX)/32-1], &pat->addr, 
			 sizeof(key->addr[1]));
		addr_mask = (u_int32_t)-1;
		if (*prefixp != 0)
			 addr_mask <<= sizeof(addr_mask)*8 - *prefixp;
		key->w[0] = be64toh(key->w[0]) & addr_mask;

		prefix += MAX_TRIE_IPV4_PREFIX-32;
		*prefixp = prefix;
		return (true);

	case AXA_P_WATCH_IPV6:
		if (!ck_num(emsg, "IPv6 address length", len, 1, 16))
			return (false);
		if (!ck_num(emsg, "prefix length", prefix, 1, len*8))
			return (false);
		if (!ck_num(emsg, "address length", len, (prefix+7)/8, 16))
			return (false);
		/* Use 64 or 128 bits for IPv6 keys. */
		memcpy(&key->addr6, &pat->addr6, sizeof(key->addr6));
		key->w[0] = be64toh(key->w[0]);
		if (prefix < AXA_WORD_BITS) {
			key->w[0] &= axa_word_mask(*prefixp);
			key->w[1] = 0;
		} else if (prefix > AXA_WORD_BITS) {
			key->w[1] = (be64toh(key->w[1])
				& axa_word_mask(*prefixp-64));
		}
		return (true);

	case AXA_P_WATCH_DNS:
		if (!ck_num(emsg, "domain name length", len, 1, 255))
			return (false);
		return (dns_to_key(emsg, key, prefixp, pat->dns, len));

	case AXA_P_WATCH_CH:
	case AXA_P_WATCH_ERRORS:
	default:
		AXA_FAIL("invalid key type %d", type);
	}
}

size_t
axa_trie_to_watch(axa_p_watch_t *w, const trie_node_t *node,
		  trie_type_t node_type, bool is_wild)
{
	size_t bytelen, wlen;
	trie_key_t key;
	uint n;

	memset(w, 0, sizeof(*w));
	memset(&key, 0, sizeof(key));

	bytelen = (node->bitlen + 7)/8;
	AXA_ASSERT(bytelen > 0 && bytelen <= sizeof(w->pat.dns));
	wlen = BITS_TO_AXA_WORDS(node->bitlen);
	for (n = 0; n < wlen; ++n)
		key.w[n] = htobe64(node->key.w[n]);

	switch (node_type) {
	case TRIE_IPV4:
		AXA_ASSERT(bytelen <= MAX_TRIE_IPV4_PREFIX/8
			   && bytelen > (MAX_TRIE_IPV4_PREFIX - 32)/8);
		bytelen -= (MAX_TRIE_IPV4_PREFIX - 32)/8;
		w->type = AXA_P_WATCH_IPV4;
		w->pat.addr = key.addr[MAX_TRIE_IPV4_PREFIX/32-1];
		w->prefix = node->bitlen - (MAX_TRIE_IPV4_PREFIX - 32);
		AXA_ASSERT((w->prefix == 32) == !is_wild);
		if (w->prefix < 32)
			w->flags |= AXA_P_WATCH_FG_WILD;
		break;
	case TRIE_IPV6:
		AXA_ASSERT(bytelen <= sizeof(w->pat.addr6));
		w->type = AXA_P_WATCH_IPV6;
		memcpy(&w->pat.addr6, &key.addr6, sizeof(w->pat.addr6));
		w->prefix = node->bitlen;
		AXA_ASSERT((w->prefix == 128) == !is_wild);
		if (w->prefix < 128)
			w->flags |= AXA_P_WATCH_FG_WILD;
		break;
	case TRIE_DOM:
		w->type = AXA_P_WATCH_DNS;
		if (is_wild)
			w->flags |= AXA_P_WATCH_FG_WILD;
		if (!rev_domain(w->pat.dns, key.b, bytelen))
			AXA_FAIL("bad DNS label length in node");
		break;
	default:
		AXA_FAIL("impossible trie type");
	}
	return (sizeof(*w) - sizeof(w->pat) + bytelen);
}


/*
 * Add a watch list entry to one of the two watch lists of a node.
 *	lock_free=true if we are working on a watch list in an existing trie
 *	    node or other list used by the searchers and so must accomodate
 *	    the lock-free reading by the searchers.
 */
static trie_node_t *
new_node(trie_roots_t *roots, const trie_key_t *key, size_t bitlen,
	 bool has_tval, bool is_wild, tval_t tval)
{
	trie_node_t *new;
	size_t keylen, newlen;

	AXA_ASSERT(bitlen > 0 && bitlen < sizeof(*key)*8);
	keylen = BITS_TO_TRIE_KEYLEN(bitlen);
	newlen = sizeof(*new) - sizeof(new->key) + keylen;
	new = axa_zalloc(newlen);

	new->bitlen = bitlen;
	memcpy(&new->key, key, keylen);
	if (has_tval)
		axa_tval_add(roots, WILD_TO_TVAL_LISTS(is_wild, new), tval,
			     0, false);

	__sync_synchronize();

	return (new);
}

/*
 * Free all of a node that was never published to searchers
 * or that is in a dead-pool that no searchers care about.
 */
void
axa_trie_node_free(trie_node_t *node)
{
	if (node->exact != NULL)
		free(node->exact);
	if (node->wild != NULL)
		free(node->wild);
	free(node);
}

/*
 * Find the first differing bit in two trie keys.
 */
static uint
diff_keys(const trie_key_t *key1, trie_bitlen_t bitlen1,
	  const trie_key_t *key2, trie_bitlen_t bitlen2)
{
	axa_word_t delta;
	trie_bitlen_t maxbit, bit;
	uint n;

	maxbit = min(bitlen1, bitlen2);

	/* find the first differing words */
	for (n = 0, bit = 0; bit <= maxbit; n++, bit += AXA_WORD_BITS) {
		delta = key1->w[n] ^ key2->w[n];
		if (delta != 0) {
			bit += axa_fls_word(delta);
			break;
		}
	}
	return (min(bit, maxbit));
}

/*
 * Search and optionally add to a trie.
 *	If (!create && found == NULL),
 *	    then we are searching to build a watch list.
 *	If (!create && found != NULL),
 *	    then search for a particular node.
 *	    A lock might be needed.
 *	If (create), then add tgt/bitlen and the "hit" or value to the tree.
 *	    A lock might be needed.
 */
static trie_op_result_t
trie_op(trie_roots_t *roots, trie_type_t trie_type,
	const trie_key_t *tgt, trie_bitlen_t tgt_bitlen, bool is_wild,
	bool create, tval_t new_tval, hitlist_t **hitlistp,
	axa_nmsg_idx_t field_idx, axa_nmsg_idx_t val_idx,
	trie_node_t **found)
{
	trie_node_t **rootp;
	trie_node_t *cur, *parent, *child, *new_parent, *sibling;
	int cur_num, child_num;
	trie_bitlen_t dbit;

	rootp = trie_type_to_root(roots, trie_type);

	if (found != NULL)
		*found = NULL;
	cur = *rootp;
	parent = NULL;
	cur_num = 0;
	for (;;) {
		if (cur == NULL) {
			/*
			 * There is no child here so we cannot go down.
			 * Quit with whatever we already found
			 * or add the target as a child of the current parent.
			 */
			if (!create)
				return (TRIE_OP_NOT_FOUND);
			/*
			 * There is no locking here because
			 *   - additions and deletions are locked
			 *   - pointers used by searchers, those pointing down,
			 *	always point to valid nodes until every search
			 *	agrees (by locking) that deleted nodes can
			 *	be destroyed.
			 */
			child = new_node(roots, tgt, tgt_bitlen,
					 true, is_wild, new_tval);
			if (parent == NULL)
				*rootp = child;
			else
				parent->child[cur_num] = child;
			child->parent = parent;
			if (found != NULL)
				*found = child;
			return (TRIE_OP_ADDED);
		}

		dbit = diff_keys(tgt, tgt_bitlen, &cur->key, cur->bitlen);
		/*
		 * We always have dbit <= tgt_bitlen and dbit <= cur->bitlen.
		 *
		 * We are finished searching if we matched all of the target.
		 */
		if (dbit == tgt_bitlen) {
			if (tgt_bitlen == cur->bitlen) {
				/* node's key matches the target exactly. */
				if (create) {
					/* Add new value if creating filters. */
					axa_tval_add(roots,
						     WILD_TO_TVAL_LISTS(is_wild,
							 cur),
						     new_tval, 0, true);
					if (found != NULL)
					    *found = cur;
					return (TRIE_OP_ADDED);
				}

				/* Stop with this node if just looking. */
				if (found != NULL) {
					*found = cur;
					return (TRIE_OP_FOUND);
				}
				/* Add the exact list of this node
				 * to the private list of interested outputs of
				 * the input that called us. */
				axa_hitlist_append(roots, hitlistp,
						   cur->exact,
						   field_idx, val_idx);

				/* IP address prefixes match themselves,
				 * but DNS wildcards do not. */
				if (trie_type == TRIE_DOM)
					axa_hitlist_append(roots, hitlistp,
							cur->wild,
							field_idx, val_idx);
				return (TRIE_OP_FOUND);
			}

			/* We know tgt_bitlen < cur->bitlen, which implies
			 * that the target is shorter than the current node. */

			if (!create)
				return (TRIE_OP_NOT_FOUND);

			/* Add the target as the current node's parent. */
			new_parent = new_node(roots, tgt, tgt_bitlen,
					      true, is_wild, new_tval);
			new_parent->parent = parent;
			child_num = axa_get_bitwords(cur->key.w, tgt_bitlen+1);
			new_parent->child[child_num] = cur;

			/*
			 * Add in the right order and with memory barriers
			 * so that the trie is always valid for searchers.
			 * Searchers do not use the parent pointers.
			 * The parent pointers are protected from other
			 * trie maintainers by the lock in the caller.
			 *
			 * Assume that aligned values 8-byte or smaller
			 * are atomic.
			 */
			__sync_synchronize();
			if (parent == NULL)
				*rootp = new_parent;
			else
				parent->child[cur_num] = new_parent;
			cur->parent = new_parent;
			if (found != NULL)
				*found = new_parent;
			return (TRIE_OP_ADDED);
		}

		if (dbit == cur->bitlen) {
			/* We have a partial match between of all of the
			 * current node but only a prefix of the target. */
			if (!create && found == NULL) {
				/* We are building a private hit list
				 * for an input. */
				axa_hitlist_append(roots, hitlistp, cur->wild,
						   field_idx, val_idx);
			}

			/* Continue searching. */
			parent = cur;
			cur_num = axa_get_bitwords(tgt->w, dbit);
			cur = cur->child[cur_num];
			continue;
		}


		/*
		 * dbit < tgt_bitlen and dbit < cur->bitlen,
		 * so we failed to match both the target and the current node.
		 */
		if (!create)
			return (TRIE_OP_NOT_FOUND);

		/*
		 * Insert a fork of a new parent above the current node
		 * and add the target as a sibling of the current node
		 */
		sibling = new_node(roots, tgt, tgt_bitlen,
				   true, is_wild, new_tval);
		new_parent = new_node(roots, tgt, dbit, false, false, 0);
		sibling->parent = new_parent;
		new_parent->parent = parent;
		child_num = axa_get_bitwords(tgt->w, dbit);
		new_parent->child[child_num] = sibling;
		new_parent->child[1-child_num] = cur;

		/*
		 * Add in the right order and with memory barriers
		 * so that the trie is always valid for searchers.
		 * Searchers do not use the parent pointers.
		 * The parent pointers are protected from other
		 * trie maintainers by the exclusive lock in the caller.
		 *
		 * Assume that aligned values of 8-bytes or smaller are atomic.
		 */
		__sync_synchronize();
		if (parent == NULL)
			*rootp = new_parent;
		else
			parent->child[cur_num] = new_parent;
		cur->parent = new_parent;
		if (found != NULL)
			*found = sibling;
		return (TRIE_OP_ADDED);
	}
}

/*
 * Remove the tval for an IP address or domain name given the node.
 *	Delete the trie node if it is no longer needed.
 */
void
axa_trie_node_delete(trie_roots_t *roots, trie_type_t trie_type,
		     trie_node_t *node, bool is_wild, tval_t tval)
{
	tval_list_t **tval_listp, **tval_list_otherp;
	trie_node_t **parentp, *parent;
	bool res;

	/* This lock is sufficient, in part because the tval and the
	 * containing node cannot be deleted except by the thread
	 * that owns the tval. */
	LOCK(roots);

	/* Remove the value from the correct list in the node. */
	if (is_wild) {
		tval_listp = &node->wild;
		tval_list_otherp = &node->exact;
	} else {
		tval_list_otherp = &node->wild;
		tval_listp = &node->exact;
	}

	res = axa_tval_delete(roots, tval_listp, tval);
	AXA_ASSERT_MSG(res, "failed to find watch for trie");

	/* Delete the entire node when its last value is deleted. */
	while (*tval_listp == NULL && *tval_list_otherp == NULL
	       && (node->child[0] == NULL || node->child[1] == NULL)) {

		/* Find parent's pointer to this node. */
		parent = node->parent;
		if (parent == NULL) {
			parentp = trie_type_to_root(roots, trie_type);
			AXA_ASSERT(*parentp == node);
		} else {
			parentp = &node->parent->child[0];
			if (*parentp != node) {
				parentp = &node->parent->child[1];
				AXA_ASSERT(*parentp == node);
			}
		}

		/* Link the parent to its grandchildren. */
		if (node->child[0] != NULL) {
			*parentp = node->child[0];
			node->child[0]->parent = node->parent;
		} else if (node->child[1] != NULL) {
			*parentp = node->child[1];
			node->child[1]->parent = node->parent;
		} else {
			*parentp = NULL;
		}
		/*
		 * Delete in the right order and with memory barriers
		 * so that the trie is always valid for searchers.
		 * Searchers do not use the parent pointers.
		 * The parent pointers are protected from other
		 * trie maintainers by the exclusive lock in the caller.
		 * Do not change the child pointers to avoid
		 * breaking the views of searchers.
		 *
		 * Assume that aligned values 8-byte or smaller
		 * are atomic.
		 */
		__sync_synchronize();

		if (roots->node_free == NULL)
			axa_trie_node_free(node);
		else
			roots->node_free(node);

		/* Delete the parent if it is now useless. */
		node = parent;
		if (node == NULL)
			break;
		tval_listp = &node->wild;
		tval_list_otherp = &node->exact;
	}

	UNLOCK(roots);
}

/* Add an IP address or domain name watch to the correct trie. */
bool
axa_trie_watch_add(axa_emsg_t *emsg,
		   trie_roots_t *roots,
		   trie_node_t **node,	/* added node */
		   const axa_p_watch_t *watch,	/* add this watch */
		   size_t watch_len,
		   tval_t tval)		/* with this value */
{
	trie_type_t trie_type;
	bool is_wild;
	trie_key_t key;
	trie_bitlen_t prefix;
	trie_op_result_t search_result;

	prefix = watch->prefix;
	if (!watch_to_trie_key(emsg, &key, watch->type, &prefix, &watch->pat,
			       watch_len - (sizeof(*watch)
					    - sizeof(watch->pat))))
		return (false);

	switch ((axa_p_watch_type_t)watch->type) {
	case AXA_P_WATCH_DNS:
		trie_type = TRIE_DOM;
		is_wild = (watch->flags & AXA_P_WATCH_FG_WILD) != 0;
		break;
	case AXA_P_WATCH_IPV4:
		trie_type = TRIE_IPV4;
		is_wild = (watch->prefix < 32);
		break;
	case AXA_P_WATCH_IPV6:
		trie_type = TRIE_IPV6;
		is_wild = (watch->prefix < 128);
		break;
	case AXA_P_WATCH_CH:
	case AXA_P_WATCH_ERRORS:
	default:
		AXA_FAIL("impossible trie type");
	}

	LOCK(roots);
	search_result = trie_op(roots, trie_type, &key, prefix, is_wild,
				true, tval, NULL, AXA_NMSG_IDX_NONE,
				AXA_NMSG_IDX_NONE, node);
	UNLOCK(roots);
	switch (search_result) {
	case TRIE_OP_FOUND:
	case TRIE_OP_PARTIAL:
	case TRIE_OP_NOT_FOUND:
		break;
	case TRIE_OP_ADDED:
		return (true);
	}

	AXA_FAIL("impossible trie_op() result %d", search_result);
}

static void
trie_search(trie_roots_t *roots, trie_type_t trie_type,
	    const trie_key_t *tgt, trie_bitlen_t tgt_bitlen, bool is_wild,
	    hitlist_t **hitlistp,
	    axa_nmsg_idx_t field_idx, axa_nmsg_idx_t val_idx)
{
	trie_op_result_t result;

	result = trie_op(roots, trie_type, tgt, tgt_bitlen, is_wild,
			 false, 0, hitlistp, field_idx, val_idx, NULL);
	switch (result) {
	case TRIE_OP_FOUND:
	case TRIE_OP_PARTIAL:
	case TRIE_OP_NOT_FOUND:
		return;
	case TRIE_OP_ADDED:
		break;
	}
	AXA_FAIL("impossible trie_op() result %d", result);
}

/* Get a list of trie values related to an IP address. */
void
axa_trie_search_su(trie_roots_t *roots, const axa_socku_t *su,
		   hitlist_t **hitlistp,
		   axa_nmsg_idx_t field_idx, axa_nmsg_idx_t val_idx)
{
	trie_key_t key;

	switch (su->sa.sa_family) {
	case AF_INET:
		key.w[0] = be32toh(su->ipv4.sin_addr.s_addr);
		trie_search(roots, TRIE_IPV4, &key, MAX_TRIE_IPV4_PREFIX, false,
			    hitlistp, field_idx, val_idx);
		break;
	case AF_INET6:
		/* first align to int64 boundary */
		memcpy(&key.addr6, &su->ipv6.sin6_addr, sizeof(key.addr6));
		key.w[0] = be64toh(key.w[0]);
		key.w[1] = be64toh(key.w[1]);
		trie_search(roots, TRIE_IPV6, &key, MAX_TRIE_IPV6_PREFIX, false,
			    hitlistp, field_idx, val_idx);
		break;
	default:
		AXA_FAIL("bad address family");
	}
}

/* Get a list of watches interested in a domain. */
bool					/* false=bogus domain name */
axa_trie_search_dom(axa_emsg_t *emsg, trie_roots_t *roots,
		    const uint8_t *name, uint name_len, hitlist_t **hitlistp,
		    axa_nmsg_idx_t field_idx, axa_nmsg_idx_t val_idx)
{
	trie_key_t key;
	trie_bitlen_t prefix;

	AXA_ASSERT(name_len > 0);
	if (!dns_to_key(emsg, &key, &prefix, name, name_len))
		return (false);
	trie_search(roots, TRIE_DOM, &key, prefix, false, hitlistp,
		    field_idx, val_idx);
	return (true);
}

static void
trie_free(trie_node_t **rootp)
{
	trie_node_t *cur, *child, *parent;

	cur = *rootp;
	while (cur != NULL) {
		/* depth first and to the left */
		child  = cur->child[0];
		if (child != NULL) {
			cur = child;
			continue;
		}
		child  = cur->child[1];
		if (child != NULL) {
			cur = child;
			continue;
		}

		/* delete this terminal node and then its parent */
		if (cur->exact != NULL) {
			free(cur->exact);
			cur->exact = NULL;
		}
		if (cur->wild != NULL) {
			free(cur->wild);
			cur->exact = NULL;
		}
		parent = cur->parent;
		if (parent == NULL)
			*rootp = NULL;
		else
			parent->child[parent->child[1] == cur] = NULL;
		free(cur);
		cur = parent;
	}
}

/* Delete all three tries held by a trie_roots_t */
void
axa_tries_free(trie_roots_t *roots)
{
	trie_free(&roots->ipv4_root);
	trie_free(&roots->ipv6_root);
	trie_free(&roots->dom_root);
}

static hitlist_t *
hitlist_create(uint len)
{
	hitlist_t *hitlist;

	hitlist = axa_zalloc(sizeof(hitlist_t) + len*sizeof(hit_t));
	hitlist->len = len;
	return (hitlist);
}

/* Add one entry to a list of outputs that should receive a message.
 *	Locking is unneeded because hit lists are private. */
static void
hitlist_add(const trie_roots_t *roots, hitlist_t **hitlistp, tval_t tval,
	    axa_nmsg_idx_t field_idx, axa_nmsg_idx_t val_idx)
{
	hitlist_t *hitlist, *new_hitlist;
	hit_t *hit;
	int hitlist_max, newlen;

	hitlist = *hitlistp;
	if (hitlist == NULL) {
		hitlist = hitlist_create(2);
		*hitlistp = hitlist;
	} else {
		/* Declare success if an entry for the same client
		 * is already present */
		if (roots->hitlist_find != NULL
		    && roots->hitlist_find(hitlist, tval))
			return;

		/* Otherwise expand the list it has no room. */
		if (hitlist->in_use >= hitlist->len) {
			if (roots->hitlist_max == 0)
				hitlist_max = 10;
			else
				hitlist_max = roots->hitlist_max;

			AXA_ASSERT(hitlist->in_use == hitlist->len);
			AXA_ASSERT(hitlist->len < hitlist_max);
			newlen = hitlist->len * 2;
			if (newlen > hitlist_max)
				newlen = hitlist_max;
			new_hitlist = hitlist_create(newlen);
			new_hitlist->in_use = hitlist->in_use;
			memcpy(new_hitlist->hits, hitlist->hits,
			       hitlist->in_use*sizeof(hit_t));

			free(hitlist);
			hitlist = new_hitlist;
			*hitlistp = hitlist;
		}
	}

	hit = &hitlist->hits[hitlist->in_use++];
	hit->tval = tval;
	hit->field_idx = field_idx;
	hit->val_idx = val_idx;
}

void
axa_hitlist_append(const trie_roots_t *roots,
		   hitlist_t **hitlistp,
		   const tval_list_t *tval_list,
		   axa_nmsg_idx_t field_idx, axa_nmsg_idx_t val_idx)
{
	int i;

	if (tval_list == NULL)
		return;

	/* Add the values of a trie node to a hit list
	 * Add hits in the order in which they were defined. */
	for (i = 0; i < tval_list->in_use; ++i) {
		hitlist_add(roots, hitlistp, tval_list->tvals[i],
			    field_idx, val_idx);
	}
}
