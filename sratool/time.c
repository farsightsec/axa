/*
 * SIE Remote Access (SRA) ASCII tool
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

#include "sratool.h"

void
convert_seconds(uint32_t seconds, uint32_t *d, uint32_t *h, uint32_t *m,
        uint32_t *s)
{
	uint32_t d1, s1;

	d1 = floor(seconds / 86400);
	s1 = seconds - 86400 * d1;

	*d = d1;
	*s = s1;

	*h = floor((*s) / 3600);
	*s -= 3600 * (*h);

	*m = floor((*s) / 60);
	*s -= 60 * (*m);
}

const char *
convert_timeval(struct timeval *t)
{
	int n;
	struct timeval r, e;
	static char buf[BUFSIZ];
	uint32_t day, hour, min, sec;

	gettimeofday(&e, NULL);
	PTIMERSUB(&e, t, &r);
	convert_seconds((u_int32_t)r.tv_sec, &day, &hour, &min, &sec);
	n = 0;
	if (day) {
		n += snprintf(buf + n, BUFSIZ,
				(day  == 1 ? "%d day "   : "%d days "), day);
	}
	if (hour) {
		n += snprintf(buf + n, BUFSIZ,
				(hour == 1 ? "%d hour "  : "%d hours "), hour);
	}
	if (min) {
		n += snprintf(buf + n, BUFSIZ,
				(min  == 1 ? "%d minute ": "%d minutes "), min);
	}
	if (sec) {
		n += snprintf(buf + n, BUFSIZ,
				(sec  == 1 ? "%d second": "%d seconds"), sec);
	}
	if (n == 0) {
		n = snprintf(buf + n, BUFSIZ, "<1 second");
	}
	buf[n] = 0;

	return buf;
}
