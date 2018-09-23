/*
 * Open an output nmsg stream for output or forwarding by sratunnel or sratool.
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

#include <axa/open_nmsg_out.h>
#include <axa/socket.h>

#include <errno.h>
#include <fcntl.h>
#include <string.h>
#include <unistd.h>

bool axa_nmsg_out_json = false;		/* true == emit nmsgs as jsonl blobs */
bool axa_out_file_append = false;	/* true == append to output file */
int axa_nmsg_output_fd = 0;		/* fd for nmsg file-based outputs */


/*
 * Parse
 *	host,port
 *	tcp:host,port
 *	udp:host,port
 *	file:filename
 * Return -1=syntax error,  0=bad host,port or filename,  out_nmsg_output set
 */
int
axa_open_nmsg_out(axa_emsg_t *emsg,
		  nmsg_output_t *out_nmsg_output, int *out_sock_type,
		  const char *addr0, bool output_buffering)
{
	const char *addr;
	axa_socku_t su;
	struct addrinfo *ai;
	bool isfile, json = false;
	int s;

	if (AXA_CLITCMP(addr0, "tcp:")) {
		addr = strchr(addr0, ':')+1;
		*out_sock_type = SOCK_STREAM;
		isfile = false;
	} else if (AXA_CLITCMP(addr0, "udp:")) {
		addr = strchr(addr0, ':')+1;
		*out_sock_type = SOCK_DGRAM;
		isfile = false;
	} else if (AXA_CLITCMP(addr0, "file:")) {
		addr = strchr(addr0, ':')+1;
		isfile = true;
	} else if (AXA_CLITCMP(addr0, "file_json:")) {
		addr = strchr(addr0, ':')+1;
		isfile = true;
		json = true;
		axa_nmsg_out_json = true;
	} else {
		addr = addr0;
		*out_sock_type = SOCK_DGRAM;
		isfile = false;
	}
	if (*addr == '\0') {
		axa_pemsg(emsg, "missing address or file name in \"%s\"",
			  addr0);
		return (-1);
	}

	if (isfile) {
		s = open(addr, axa_out_file_append ?
				O_WRONLY | O_CREAT | O_APPEND :
				O_WRONLY | O_CREAT | O_TRUNC, 0666);
		if (s < 0) {
			axa_pemsg(emsg, "open(%s): %s", addr, strerror(errno));
			return (0);
		}

	} else {
		if (!axa_get_srvr(emsg, addr, false, &ai))
			return (0);

		memset(&su, 0, sizeof(su));
		memcpy(&su.sa, ai->ai_addr, ai->ai_addrlen);
		freeaddrinfo(ai);

		s = socket(su.sa.sa_family, *out_sock_type, 0);
		if (s < 0) {
			axa_pemsg(emsg, "socket(%s): %s",
				  addr, strerror(errno));
			return (0);
		}

		if (!axa_set_sock(emsg, s, addr, 0, false)) {
			close(s);
			return (0);
		}

		if (0 > connect(s, &su.sa, AXA_SU_LEN(&su))) {
			axa_pemsg(emsg, "connect(%s): %s",
				  addr, strerror(errno));
			close(s);
			return (0);
		}
	}
	axa_nmsg_output_fd = s;

	if (!isfile && *out_sock_type == SOCK_DGRAM) {
		*out_nmsg_output = nmsg_output_open_sock(s, NMSG_WBUFSZ_ETHER);
		if (out_nmsg_output == NULL) {
			axa_pemsg(emsg, "nmsg_output_open_sock(%s): failed",
				  addr);
			close(s);
			return (0);
		}
	} else {
		if (json)
			*out_nmsg_output = nmsg_output_open_json(s);
		else
			*out_nmsg_output = nmsg_output_open_file(s, NMSG_WBUFSZ_MAX);
		if (out_nmsg_output == NULL) {
			axa_pemsg(emsg, "nmsg_output_open_file(%s) failed",
				  addr);
			close(s);
			return (0);
		}
	}

	if (output_buffering == false)
		/* unbuffer all nmsg outputs */
		nmsg_output_set_buffered(*out_nmsg_output, false);

	return (1);
}
