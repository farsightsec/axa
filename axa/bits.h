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

#ifndef AXA_BITS_H
#define AXA_BITS_H

#include <sys/types.h>
#include <stdint.h>
#include <stdbool.h>

typedef uint64_t axa_word_t;
typedef uint32_t axa_n_long_t;

#define AXA_WORD_BITS		(sizeof(axa_word_t)*8)

#define BYTES_TO_AXA_WORDS(b)	(((b)+sizeof(axa_word_t)-1)		\
				 / sizeof(axa_word_t))

#define AXA_WORDS_TO_BYTES(w)	((w)*sizeof(axa_word_t))

#define BITS_TO_AXA_WORDS(b)	(((b) + AXA_WORD_BITS-1) / AXA_WORD_BITS)


#endif /* AXA_BITS_H */
