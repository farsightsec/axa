/*
 * Socket utilities
 *
 *  Copyright (c) 2023 DomainTools LLC
 *  Copyright (c) 2014-2018 by Farsight Security, Inc.
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
#include <axa/socket.h>

#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#ifdef __linux
#include <bsd/string.h>			/* for strlcpy() */
#endif
#include <string.h>
#include <stdlib.h>
#include <netinet/tcp.h>
#include <unistd.h>


#define IPV4_CHARS     ".0123456789"
#define IPV6_CHARS     IPV4_CHARS":abcdefABCDEF"


/* Make a socket address from an IPv4 address and a port number */
static axa_socku_t *
mk_inet_su(axa_socku_t *su,		/* put it here */
	   const struct in_addr *addrp, /* 0=INADDR_ANY */
	   in_port_t port)
{
	in_addr_t addr4;

	/* allow source to be part of target */
	addr4 = addrp ? addrp->s_addr : 0;

	memset(su, 0, sizeof(*su));	/* assume INADDR_ANY=0 */
	su->sa.sa_family = AF_INET;
#ifdef HAVE_SA_LEN
	su->sa.sa_len = sizeof(struct sockaddr_in);
#endif
	su->ipv4.sin_port = port;
	if (addrp)
		su->ipv4.sin_addr.s_addr = addr4;

	return (su);
}

/*
 * Make socket address from an IPv6 address, a scope ID, and a port number.
 */
static axa_socku_t *
mk_inet6_su(axa_socku_t *su,		/* put it here */
	    const struct in6_addr *addrp,   /* NULL=INADDR_ANY */
	    uint32_t scope_id,
	    in_port_t port)
{
	memset(su, 0, sizeof(*su));	/* assume INADDR_ANY=NULL */
	su->sa.sa_family = AF_INET6;
#ifdef HAVE_SA_LEN
	su->sa.sa_len = sizeof(struct sockaddr_in6);
#endif
	su->ipv6.sin6_port = port;
	if (addrp != NULL)
		su->ipv6.sin6_addr = *addrp;
	su->ipv6.sin6_scope_id = scope_id;
	return (su);
}

/*
 * Get a socket address from a dotted quad or IPv6 string.
 */
bool
axa_str_to_su(axa_socku_t *sup, const char *str)
{
	char buf[INET6_ADDRSTRLEN];
	struct in_addr addr4;
	struct in6_addr addr6;
	size_t i, len;
	const char *p;

	str = axa_strip_white(str, &len);
	if (len == 0 || len >= INET6_ADDRSTRLEN)
		return (false);

	i = strspn(str, IPV4_CHARS);
	if (i == len && i < INET_ADDRSTRLEN) {
		if (0 < inet_aton(str, &addr4)) {
			if (sup != NULL)
				mk_inet_su(sup, &addr4, 0);
			return (true);
		}
	}

	/* Require at least one colon among valid IPv6 characters. */
	p = str+i;
	i += strspn(p, IPV6_CHARS);
	if (i != len)
		return (false);
	p = strchr(p, ':');
	if (p == NULL || p >= &str[len])
		return (false);

	/*
	 * Try IPv6 only after failing to understand the string as IPv4
	 * and making other quick checks.
	 * The quick checks can be fooled by junk such as 123:aaaaaaaa
	 *
	 * inet_pton() does not like blanks or terminal '\n'
	 * It is also too smart by half and assumes that its void* is a
	 * struct sockaddr*.
	 *
	 * inet_pton() does not know about scopes.
	 *
	 * When inet_pton() decodes an IPv4 address, it sticks it
	 * 4 bytes before the start of an IPv6 buffer it is given.
	 * Since we have already checked for IPv4, that should not be
	 * a problem.
	 */
	if (str[len] != '\0') {
		memcpy(buf, str, len);
		buf[len] = '\0';
		str = buf;
	}
	if (0 < inet_pton(AF_INET6, str, &addr6)) {
		if (sup)
			mk_inet6_su(sup, &addr6, 0, 0);
		return (true);
	}

	return (false);
}

bool
axa_data_to_su(axa_socku_t *su, const void *data, size_t data_len)
{
	memset(su, 0, sizeof(*su));
	if (data_len == sizeof(su->ipv4.sin_addr)) {
		su->sa.sa_family = AF_INET;
		memcpy(&su->ipv4.sin_addr, data,
		       sizeof(su->ipv4.sin_addr));
#ifdef HAVE_SA_LEN
		su->sa.sa_len = sizeof(su->ipv4.sin_addr);
#endif
	} else if (data_len == sizeof(su->ipv6.sin6_addr)) {
		su->sa.sa_family = AF_INET6;
		memcpy(&su->ipv6.sin6_addr, data,
		       sizeof(su->ipv6.sin6_addr));
#ifdef HAVE_SA_LEN
		su->sa.sa_len = sizeof(su->ipv6.sin6_addr);
#endif
	} else {
		return (false);
	}
	return (true);
}

bool
axa_ip_to_su(axa_socku_t *su, const void *ip, uint family)
{
	memset(su, 0, sizeof(*su));
	if (family == AF_INET) {
		/* The source need not be aligned. */
		memcpy(&su->ipv4.sin_addr, ip,
		       sizeof(su->ipv4.sin_addr));
		su->sa.sa_family = family;
#ifdef HAVE_SA_LEN
		su->sa.sa_len = sizeof(su->ipv4.sin_addr);
#endif
	} else if (family == AF_INET6) {
		memcpy(&su->ipv6.sin6_addr, ip,
		       sizeof(su->ipv6.sin6_addr));
		su->sa.sa_family = family;
#ifdef HAVE_SA_LEN
		su->sa.sa_len = sizeof(su->ipv6.sin6_addr);
#endif
	} else {
		return (false);
	}
	return (true);
}

char *
axa_su_to_str(char *str, size_t str_len, char portc, const axa_socku_t *su)
{
	char addr_str[INET6_ADDRSTRLEN];
	const char *cp;

	memset(str, 0, str_len);

	if (su->sa.sa_family == AF_UNIX) {
		strlcpy(str, su->sun.sun_path, str_len);
		return (str);
	}

	if (su->sa.sa_family == AF_INET) {
		cp = inet_ntop(AF_INET, &su->ipv4.sin_addr,
			       addr_str, sizeof(addr_str));
	} else  if (su->sa.sa_family == AF_INET6) {
		cp = inet_ntop(AF_INET6, &su->ipv6.sin6_addr,
			       addr_str, sizeof(addr_str));
	} else {
		AXA_FAIL("bad address family %d in su_to_str()",
			 su->sa.sa_family);
	}
	if (cp == NULL)
		strlcpy(addr_str, "???", sizeof(addr_str));
	if (AXA_SU_PORT(su) == 0) {
		strlcpy(str, addr_str, str_len);
	} else {
		snprintf(str, str_len, "%s%c%d",
			 addr_str, portc, ntohs(AXA_SU_PORT(su)));
	}
	return (str);
}

void
axa_bits_to_mask(struct in6_addr *mask, int bits)
{
	int wordno, i;

	for (wordno = 0; wordno < 4; ++wordno) {
		i = bits - wordno*32;
		if (i >= 32) {
			mask->s6_addr32[wordno] = 0xffffffff;
			continue;
		}
		if (i <= 0) {
			mask->s6_addr32[wordno] = 0;
			continue;
		}
		mask->s6_addr32[wordno] = htonl(0xffffffff << (32-i));
	}
}

/*
 * Get an IP address and netmask.
 */
int					/* # of bits or -1=error */
axa_str_to_cidr(axa_emsg_t *emsg, axa_socku_t *su, const char *str)
{
	char addr_str[INET6_ADDRSTRLEN];
	struct in6_addr mask6;
	const char *bitsp;
	char *p;
	size_t str_len, addr_len, bits_len;
	u_long bits;
	int wordno;

	str = axa_strip_white(str, &str_len);
	bitsp = strchr(str, '/');

	if (bitsp == NULL) {
		addr_len = str_len;
	} else {
		addr_len = bitsp - str;
	}
	if (addr_len == 0) {
		axa_pemsg(emsg, "invalid IP address \"%s\"", str);
		return (-1);
	}
	if (addr_len >= sizeof(addr_str)) {
		axa_pemsg(emsg, "invalid IP address \"%.*s\"",
			  (int)addr_len, str);
		return (-1);
	}
	memcpy(addr_str, str, addr_len);
	addr_str[addr_len] = '\0';
	if (!axa_str_to_su(su, addr_str)) {
		axa_pemsg(emsg, "invalid IP address \"%s\"", addr_str);
		return (-1);
	}
	axa_su_to_str(addr_str, sizeof(addr_str), '.', su);

	if (bitsp == NULL) {
		if (su->sa.sa_family == AF_INET6) {
			bitsp = "128";
			bits_len = 3;
		} else {
			bitsp = "32";
			bits_len = 2;
		}
		bits = 128;
	} else {
		bits_len = str_len - addr_len - 1;
		bits = strtoul(++bitsp, &p, 10);
		if (*bitsp == '\0' || p < bitsp+bits_len
		    || bits < 1 || bits > 128
		    || (bits > 32 && su->sa.sa_family == AF_INET)) {
			axa_pemsg(emsg, "invalid prefix length \"/%.*s\"",
				  (int)str_len, bitsp);
			return (-1);
		}
		if (su->sa.sa_family == AF_INET)
			bits += 128-32;
	}

	axa_bits_to_mask(&mask6, bits);
	if (su->sa.sa_family == AF_INET) {
		if ((su->ipv4.sin_addr.s_addr & ~mask6.s6_addr32[3]) == 0)
			return (bits-(128-32));
	} else {
		wordno = 0;
		for (;;) {
			if (wordno >= 4)
				return (bits);
			if ((su->ipv6.sin6_addr.s6_addr32[wordno]
			     & ~mask6.s6_addr32[wordno]) != 0)
				break;
			++wordno;
		}
	}
	axa_pemsg(emsg, "%s does not start on a %.*s-bit CIDR boundary",
		  addr_str, (int)bits_len, bitsp);
	return (-1);
}

/*
 * Parse a "hostname,port" string specifying an SRA or RAD server.
 */
bool
axa_get_srvr(axa_emsg_t *emsg, const char *addr_port,
	     bool passive, struct addrinfo **resp)
{
	char *buf;
	char *host, *port;
	struct addrinfo hints;
	int error;

	*resp = NULL;

	/* Get the hostname and from separate it from the port number. */
	buf = axa_strdup(addr_port);
	port = buf;
	host = strsep(&port, ",/");
	if (host == NULL) {
		free(buf);
		return (false);
	}
	if (*host == '\0') {
		if (passive) {
			host = NULL;
		} else {
			axa_pemsg(emsg, "missing host name in \"%s\"",
				  addr_port);
			free(buf);
			return (false);
		}
	}
	if (passive && host && strcmp(host, "*") == 0)
		host = NULL;
	if (port == NULL) {
		axa_pemsg(emsg, "missing port in \"%s\"", addr_port);
		free(buf);
		return (false);
	}

	memset(&hints, 0, sizeof(hints));
	hints.ai_family = PF_UNSPEC;
	/* The IP address might might be used by the caller for UDP. */
	hints.ai_socktype = SOCK_STREAM;
	hints.ai_protocol = IPPROTO_TCP;
	hints.ai_flags = AI_ADDRCONFIG;
	if (passive)
		hints.ai_flags |= AI_PASSIVE;

	error = getaddrinfo(host, port, &hints, resp);
	if (error != 0) {
		axa_pemsg(emsg, "%s: %s", addr_port, gai_strerror(error));
		free(buf);
		return (false);
	}

	free(buf);
	return (true);
}

/*
 * Set socket or other communications file descriptor options.
 *
 * WARNING: It is strongly recommended that callers pass only a value of zero
 * for req_bufsize and defer to the wisdom of the kernel, rather than risk
 * inadvertently clamping auto-sizing and hurting performance.
  */
bool					/* false=emsg has an error message */
axa_set_sock(axa_emsg_t *emsg, int s, const char *label,
	     int req_bufsize, bool nonblock)
{
	int on;
	int protocol;
	uint type;
	int bufsize;
	socklen_t len;

	if (0 > fcntl(s, F_SETFD, FD_CLOEXEC)) {
		axa_pemsg(emsg, "fcntl(%s, F_SETFD, FD_CLOEXEC): %s",
			  label, strerror(errno));
		return (false);
	}

	if (nonblock && -1 == fcntl(s, F_SETFL,
				    fcntl(s, F_GETFL, 0) | O_NONBLOCK)) {
		axa_pemsg(emsg, "fcntl(%s, O_NONBLOCK): %s",
			  label, strerror(errno));
		return (false);
	}

	len = sizeof(type);
	if (0 > getsockopt(s, SOL_SOCKET, SO_TYPE, &type, &len)) {
		/* Do not worry about not setting socket options on pipes. */
		if (errno == ENOTSOCK)
			return (true);

		/* Hope for the best despite this error. */
		axa_trace_msg("getsockopt(%s, SO_TYPE): %s",
			      label, strerror(errno));

	} else if (type != SOCK_STREAM && type != SOCK_DGRAM) {
		/* Do not try to set socket options on files. */
		return (true);
	}

	/* We know or are assuming that we have a socket instead of a file. */

	if (req_bufsize > 0) {
		bufsize = req_bufsize;
		if (0 > setsockopt(s, SOL_SOCKET, SO_RCVBUF,
				   &bufsize, sizeof(bufsize))) {
			/* Hope for the best despite this error. */
			axa_trace_msg("setsockopt(%s, SO_RCVBUF=%d): %s",
				      label, bufsize, strerror(errno));
		}
		bufsize = req_bufsize;
		if (0 > setsockopt(s, SOL_SOCKET, SO_SNDBUF,
				   &bufsize, sizeof(bufsize))) {
			/* Hope for the best despite this error. */
			axa_trace_msg("setsockopt(%s, SO_SNDBUF=%d): %s",
				      label, bufsize, strerror(errno));
		}
	}


#ifdef SO_PROTOCOL
	len = sizeof(protocol);
	if (0 > getsockopt(s, SOL_SOCKET, SO_PROTOCOL, &protocol, &len)) {
		/* hope for the best despite this error */
		axa_trace_msg("getsockopt(%s, SO_PROTOCOL): %s",
			      label, strerror(errno));
		protocol = -1;
	}
#else
	/*
	 * Without getsockopt(..SOL_SOCKET, SO_PROTOCOL..) to check that we
	 * have a TCP/IP socket (e.g. on OS X),
	 * there will be errors as we assume that all stream or datagram
	 * sockets are TCP/IP sockets and try set UDP or TCP options
	 * on UNIX domain sockets.
	 */
	protocol = -1;
#endif

	if (protocol == IPPROTO_TCP
	    || (protocol == -1 && type == SOCK_STREAM)) {
		on = 1;
		if (0 > setsockopt(s, IPPROTO_TCP, SO_KEEPALIVE,
				   &on, sizeof(on))) {
			/* hope for the best despite this error */
			axa_trace_msg("probably spurious error setsockopt("
				      "%s, SO_KEEPALIVE): %s",
				      label, strerror(errno));
		}
		on = 1;
		if (0 > setsockopt(s, IPPROTO_TCP, TCP_NODELAY,
				   &on, sizeof(on))) {
			/* hope for the best despite this error */
			axa_trace_msg("probably spurious error setsockopt("
				      "%s, TCP_NODELAY): %s",
				      label, strerror(errno));
		}
	} else if (protocol == IPPROTO_UDP
		   || (protocol == -1 && type == SOCK_DGRAM)) {
		on = 1;
		if (0 > setsockopt(s, SOL_SOCKET, SO_BROADCAST,
				   &on, sizeof(on))) {
			/* hope for the best despite this error */
			axa_trace_msg("probably spurious error setsockopt("
				      "%s, SO_BROADCAST): %s",
				      label, strerror(errno));
		}
	}

	return (true);
}
