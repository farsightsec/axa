/*
 * Kickfile routines
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

#ifndef AXA_KICKFILE_H
#define AXA_KICKFILE_H

struct axa_kickfile {
	char *cmd;
	char *curname;
	char *axa_basename;
	char *tmpname;
	char *suffix;
};

void axa_kickfile_destroy(struct axa_kickfile **);
void axa_kickfile_exec(struct axa_kickfile *);
void axa_kickfile_rotate(struct axa_kickfile *);

#endif /* AXA_KICKFILE_H */
