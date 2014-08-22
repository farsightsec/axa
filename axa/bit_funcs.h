/*
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

#ifndef AXA_BIT_FUNCS_H
#define AXA_BIT_FUNCS_H

#include <axa/bits.h>


static inline axa_word_t
axa_word_mask(uint b)
{
	axa_word_t m;

	m = (axa_word_t)(-1);
	if (b != 0)
		m <<= (AXA_WORD_BITS - b);
	return (m);
}

static inline axa_n_long_t
axa_n_long_mask(uint b)
{
	axa_n_long_t m;

	m = (axa_n_long_t)(-1);
	if (b != 0)
		m <<= (sizeof(axa_n_long_t)*8 - b);
	return (m);
}


#define AXA_MAKE_BIT(bit, w, bit_num) do {				    \
	(w) += (bit_num) / AXA_WORD_BITS;				    \
	(bit_num) %= AXA_WORD_BITS;					    \
	(bit) = 1;							    \
	if ((bit_num) < AXA_WORD_BITS-1)				    \
		(bit) <<= (AXA_WORD_BITS-1 - (bit_num));		    \
} while (0)


/* Find the index of the most significant non-zero bit in a 64-bit word.
 *	Answer with 64 if the word is 0. */
#define axa_fls_word(w) (((w) == 0) ? (uint)AXA_WORD_BITS		\
			 : (uint)__builtin_clzll((axa_word_t)(w)))


/* Get a numbered bit from an array of 64-bit words */
static inline bool
axa_get_bitwords(const axa_word_t *w, uint bit_num)
{
	axa_word_t bit;

	AXA_MAKE_BIT(bit, w, bit_num);
	return ((*w & bit) != 0);
}

/* Set a numbered bit in an array of 64-bit words. */
static inline bool			/* previous value */
axa_set_bitwords(axa_word_t *w, uint bit_num)
{
	axa_word_t bit;

	AXA_MAKE_BIT(bit, w, bit_num);
	if ((*w & bit) != 0)
		return (true);
	*w |= bit;
	return (false);
}

/* Clear a numbered bit in an array of 64-bit words. */
static inline bool			/* previous value */
axa_clr_bitwords(axa_word_t *w, uint bit_num)
{
	axa_word_t bit;

	AXA_MAKE_BIT(bit, w, bit_num);
	if ((*w & bit) == 0)
		return (false);
	*w &= ~bit;
	return (true);
}


extern uint axa_find_bitwords(axa_word_t *w, uint bits_len);


#endif /* AXA_BIT_FUNCS_H */
