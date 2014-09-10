/**
 * Bits in words.
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

#ifndef AXA_BITS_H
#define AXA_BITS_H

#include <sys/types.h>
#include <stdint.h>
#include <stdbool.h>


typedef uint64_t axa_word_t;

#define AXA_WORD_BITS		(sizeof(axa_word_t)*8)

#define BYTES_TO_AXA_WORDS(b)	(((b)+sizeof(axa_word_t)-1)		\
				 / sizeof(axa_word_t))

#define AXA_WORDS_TO_BYTES(w)	((w)*sizeof(axa_word_t))

#define BITS_TO_AXA_WORDS(b)	(((b) + AXA_WORD_BITS-1) / AXA_WORD_BITS)


static inline axa_word_t
axa_word_mask(uint b)
{
	axa_word_t m;

	m = (axa_word_t)(-1);
	if (b != 0)
		m <<= (AXA_WORD_BITS - b);
	return (m);
}

#define AXA_MAKE_BIT(bit, w, bit_num) do {				    \
	(w) += (bit_num) / AXA_WORD_BITS;				    \
	(bit_num) %= AXA_WORD_BITS;					    \
	(bit) = 1;							    \
	if ((bit_num) < AXA_WORD_BITS-1)				    \
		(bit) <<= (AXA_WORD_BITS-1 - (bit_num));		    \
} while (0)


/**
 *  Find the index of the most significant non-zero bit in a 64-bit word
 *	by counting its leading zeros.
 *  \param[in] w axa word
 *  \return the index of the MSb or 64 if the word is 0
 */
#define axa_fls_word(w) (((w) == 0) ? (uint)AXA_WORD_BITS		\
			 : (uint)__builtin_clzll((axa_word_t)(w)))


/**
 *  Get a numbered bit from an array of 64-bit words
 *  \param[in] w pointer to an axa word
 *  \param[in] bit_num bit number to return
 *  \return the value of the specified bit
 */
static inline bool
axa_get_bitwords(const axa_word_t *w, uint bit_num)
{
	axa_word_t bit;

	AXA_MAKE_BIT(bit, w, bit_num);
	return ((*w & bit) != 0);
}

/**
 *  Set a numbered bit in an array of 64-bit words.
 *  \param[in] w pointer to an axa word
 *  \param[in] bit_num bit number to set
 *  \return the previous value of the specified bit
 */
static inline bool
axa_set_bitwords(axa_word_t *w, uint bit_num)
{
	axa_word_t bit, old;

	AXA_MAKE_BIT(bit, w, bit_num);
	old = __sync_fetch_and_or(w, bit);
	return ((old & bit) != 0);
}

/**
 *  Clear a numbered bit in an array of 64-bit words.
 *  \param[in] w pointer to an axa word
 *  \param[in] bit_num bit number to set
 *  \return the previous value of the specified bit
 */
static inline bool
axa_clr_bitwords(axa_word_t *w, uint bit_num)
{
	axa_word_t bit, old;

	AXA_MAKE_BIT(bit, w, bit_num);
	old = __sync_fetch_and_and(w, ~bit);
	return ((old & bit) != 0);
}

/**
 *  Find the index of the first bit set in an array of 64-bit words.
 *  \param[in] w pointer to an axa word
 *  \param[in] bits_len length of bits
 *  \return index of the first bit set or bits_len * 64 if no bits are set
 */
extern uint axa_find_bitwords(axa_word_t *w, uint bits_len);


#endif /* AXA_BITS_H */
