/*
 * time utilities
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


#include <axa/axa.h>


/* compute (tv1 - tv2) in milliseconds, but clamped to AXA_DAY_SECS */
time_t
axa_tv_diff2ms(const struct timeval *tv1, const struct timeval *tv2)
{
	time_t ms;

	/* prevent overflow */
	ms = tv1->tv_sec - tv2->tv_sec;
	if (ms <= -AXA_DAY_SECS)
		return (-AXA_DAY_SECS*1000);
	if (ms >= AXA_DAY_SECS)
		return (AXA_DAY_SECS*1000);
	ms = ms*1000 + (tv1->tv_usec - tv2->tv_usec)/1000;
	return (ms);
}

time_t
axa_elapsed_ms(const struct timeval *now, struct timeval *then)
{
	time_t ms;

	ms = axa_tv_diff2ms(now, then);
	if (ms < 0) {
		/* Limit damage from reverse time jumps. */
		*then = *now;
		ms = 0;
	}
	return (ms);
}
