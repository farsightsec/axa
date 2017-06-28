/*
 * Advanced Exchange Access (AXA) nmsg stream API
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

#ifndef AXA_OPEN_NMSG_OUT_H
#define AXA_OPEN_NMSG_OUT_H

/**
 *  \defgroup axa_open_nmsg_out axa_open_nmsg_out
 *
 *  `axa_open_nmsg_out` contains NMSG stream function declaration.
 *
 * @{
 */

#include <axa/axa.h>

#include <nmsg.h>

/**
 *  Open an output nmsg stream for output or forwarding by sratunnel or
 *  sratool. Note that all nmsg output objects are unbuffered.
 *
 *  \param[out] emsg if something goes wrong, this will contain the reason
 *  \param[out] out_nmsg_output nmsg_output_t of the newly opened NMSG
 *	connection
 *  \param[out] out_sock_type will hold the type of output socket
 *	(SOCK_STREAM or SOCK_DGRAM)
 *  \param[in] addr canonical protocol/address of the format:
 *	"host,port", "tcp:host,port", "udp:host,port", "file:filename"
 *
 *  \retval -1 on error
 *  \retval 0 on bad host/port/filename
 *  \retval 1 on success and out_nmsg_output/out_sock_type will be set
 */
extern int axa_open_nmsg_out(axa_emsg_t *emsg, nmsg_output_t *out_nmsg_output,
			     int *out_sock_type, const char *addr);

/**@}*/

#endif /* AXA_OPEN_NMSG_OUT_H */
