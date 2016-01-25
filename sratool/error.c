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

/* extern: infile.c */
extern int in_file_cur;
extern in_files_t in_files[];

/* extern: main.c */
extern bool eclose;

/* extern: server.c */
extern axa_client_t client;

static void
vsub_error_msg(const char *p, va_list args)
{
	clear_prompt();
	vfprintf(stderr, p, args);
	fputc('\n', stderr);
}

static void AXA_PF(1,2)
sub_error_msg(const char *p, ...)
{
	va_list args;

	va_start(args, p);
	vsub_error_msg(p, args);
	va_end(args);
}

void AXA_PF(1,2)
error_msg(const char *p, ...)
{
	va_list args;

	va_start(args, p);
	vsub_error_msg(p, args);
	va_end(args);

	error_close(false);
}

/*
 * After an error, disconnect from the server if in "error mode".
 * And after a command error, give up on a command file set with "source".
 */
void
error_close(bool cmd_error)
{
	if (eclose && AXA_CLIENT_OPENED(&client)) {
		sub_error_msg("    disconnecting from %s after error",
			      client.io.label);
		disconnect(false);
	}

	if (cmd_error && in_file_cur > 0) {
		AXA_ASSERT(in_files[in_file_cur].name != NULL);
		sub_error_msg("    after line #%d in %s",
			  in_files[in_file_cur].lineno,
			  in_files[in_file_cur].name);
		close_in_files();
	}
}
