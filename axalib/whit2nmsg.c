/*
 * SRA whit payload to nmsg
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

#include <axa/axa_endian.h>
#include <axa/fields.h>

#include <stdlib.h>

bool
axa_whit2nmsg(axa_emsg_t *emsg, nmsg_input_t nmsg_input,
	      nmsg_message_t *msgp, axa_p_whit_t *whit, size_t whit_len)
{
	size_t msg_len;
	nmsg_message_t *msgs;
	size_t n_msgs;
	struct timespec ts;
	nmsg_res res;

	*msgp = NULL;

	msg_len = whit_len - sizeof(whit->nmsg.hdr);
	if (msg_len <= 0) {
		axa_pemsg(emsg, "truncated nmsg");
		return (false);
	}
	ts.tv_sec = AXA_P2H32(whit->nmsg.hdr.ts.tv_sec);
	ts.tv_nsec = AXA_P2H32(whit->nmsg.hdr.ts.tv_nsec);
	res = nmsg_input_read_null(nmsg_input, whit->nmsg.b, msg_len,
				   &ts, &msgs, &n_msgs);
	if (res != nmsg_res_success) {
		axa_pemsg(emsg, "nmsg_input_read_null(): %s",
			  nmsg_res_lookup(res));
		return (false);
	}
	if (n_msgs < 1 || n_msgs > 1) {
		axa_pemsg(emsg, "impossible %zd messages to decode from "
			 AXA_OP_CH_PREFIX"%d",
			 n_msgs, AXA_P2H_CH(whit->hdr.ch));
		while (n_msgs > 0)
			nmsg_message_destroy(&msgs[--n_msgs]);
		free(msgs);
		return (false);
	}

	*msgp = msgs[0];
	free(msgs);
	return (true);
}
