/*
 * SIE Remote Access (SRA) ASCII tool
 *
 *  Copyright (c) 2014-2017 by Farsight Security, Inc.
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
bool interrupted = false;		/* true when asynch-interrupted */
bool terminated = false;		/* true when time to quit */

void
sigint(int sig AXA_UNUSED)
{
	interrupted = true;
}

void
sigterm(int sig AXA_UNUSED)
{
	interrupted = true;

	/* SIGTERM ends the program. */
	terminated = true;
}
