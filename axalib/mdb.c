/*
 * AXA timestamp indexing lmdb functions
 *
 *  Copyright (c) 2018 by Farsight Security, Inc.
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

#include <axa/mdb.h>

int
axa_tsi_mdb_cmp(const MDB_val *a, const MDB_val *b)
{
	struct timespec *ts_a, *ts_b;

	ts_a = (struct timespec *)a->mv_data;
	ts_b = (struct timespec *)b->mv_data;

	if (ts_a->tv_sec > ts_b->tv_sec)
		return (1);
	if (ts_a->tv_sec < ts_b->tv_sec)
		return (-1);

	return (0);
}
