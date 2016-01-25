/*
 * SIE Remote Access (SRA) ASCII tool
 *
 *  Copyright (c) 2014-2016 by Farsight Security, Inc.
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

/* global */
in_files_t in_files[MAX_IN_FILES];	/* source command input files */
int in_file_cur = 0;			/* current input file */

void
close_in_file_cur(void)
{
	AXA_ASSERT(in_file_cur > 0 && in_file_cur < MAX_IN_FILES);

	free(in_files[in_file_cur].name);
	in_files[in_file_cur].name = NULL;

	if (in_files[in_file_cur].buf != NULL)
		free(in_files[in_file_cur].buf);

	in_files[in_file_cur].buf = NULL;
	in_files[in_file_cur].buf_size = 0;
	fclose(in_files[in_file_cur].f);
	in_files[in_file_cur].f = NULL;
	--in_file_cur;
}

void
close_in_files(void)
{
	while (in_file_cur > 0)
		close_in_file_cur();
}
