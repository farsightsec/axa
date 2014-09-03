/**
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

#ifndef AXA_OPEN_NMSG_OUT_H
#define AXA_OPEN_NMSG_OUT_H

#include <axa/axa.h>

#include <nmsg.h>

extern int axa_open_nmsg_out(axa_emsg_t *emsg, nmsg_output_t *out_nmsg_output,
			     int *out_sock_type, const char *addr);

#endif /* AXA_OPEN_NMSG_OUT_H */
