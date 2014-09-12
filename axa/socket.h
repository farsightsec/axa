/*
 * Advanced Exchange Access (AXA) socket and IP address code
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

#ifndef AXA_SOCKET_H
#define AXA_SOCKET_H

/*! \file socket.h
 *  \brief AXA socket and IP address macros and function declarations.
 *
 */


#include <axa/axa.h>

#include <net/ethernet.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <sys/socket.h>
#include <netdb.h>
#include <sys/un.h>


#ifdef __FreeBSD__
# define HAVE_SA_LEN
#else
# undef HAVE_SA_LEN
#endif

typedef union {
	struct sockaddr sa;
	struct sockaddr_in ipv4;
	struct sockaddr_in6 ipv6;
	struct sockaddr_un sun;
} axa_socku_t;
#ifndef s6_addr32
#define s6_addr32 __u6_addr.__u6_addr32
#endif

#ifdef HAVE_SA_LEN
#define AXA_SU_LEN(s) ((s)->sa.sa_len)
#else
#define AXA_SU_LEN(s) ({sa_family_t _family = (s)->sa.sa_family;	\
	(_family == AF_INET) ? (int)sizeof((s)->ipv4)			\
	: (_family == AF_INET6) ? (int)sizeof((s)->ipv6)		\
	: (_family == AF_UNIX) ? (int)(sizeof((s)->sun)			\
				       -sizeof((s)->sun.sun_path)	\
				       +strlen((s)->sun.sun_path))	\
	: -1;})
#endif

/* L-value
 *	use IPv4 port number if sa_family is AF_UNSPEC */
#define AXA_SU_PORT(su) (*((su)->sa.sa_family == AF_INET6		\
			   ? &(su)->ipv6.sin6_port			\
			   : &(su)->ipv4.sin_port))

typedef enum {
	AXA_LSOCK_TCP,
	AXA_LSOCK_UDS,
	AXA_LSOCK_PROXY_SSH
} axa_lsock_type_t;
typedef struct {
	int		s;
	axa_socku_t	su;
	axa_lsock_type_t	type;
} axa_lsock_t;

#define AXA_POLL_IN	(POLLIN | POLLRDNORM | POLLRDBAND | POLLPRI)
#define AXA_POLL_OUT	(POLLOUT | POLLWRNORM | POLLWRBAND)
#define AXA_POLL_OFF	(POLLERR | POLLHUP | POLLNVAL)
#ifndef INFTIM
#define INFTIM (-1)			/* for Linux */
#endif


/* Errors on UDP output that are not necessarily fatal
 *	At least some filters including IPFW say EACCES on hits,
 *	so treat EACCES like Unreachables. */
#define AXA_IGNORED_UDP_ERRNO(e) (e == ECONNREFUSED			\
				  || e == EHOSTUNREACH			\
				  || e == ENETUNREACH			\
				  || e == EHOSTDOWN			\
				  || e == ENETDOWN			\
				  || e == EACCES			\
				  || e == ENOBUFS)

/* Non-errors during non-blocking connect() */
#define AXA_CONN_WAIT_ERRORS() (errno == EAGAIN || errno == EINPROGRESS	\
				|| errno == EALREADY)


#define AXA_ADDR_WAIT_IN_USE	5	/* wait this long for a busy port */


/* socket.c */
/* INET6_ADDRSTRLEN+1+5+1 is xxxx:...:xxx/65535 */
#define AXA_SU_TO_STR_LEN dcl_max(INET6_ADDRSTRLEN+1+5+1,		\
				  sizeof(((axa_socku_t*)0)->sun.sun_path)+1)
extern char *axa_su_to_str(char *str, size_t str_len, char portc,
			   const axa_socku_t *su);
extern bool axa_data_to_su(axa_socku_t *su, const void *data, size_t data_len);
extern bool axa_ip_to_su(axa_socku_t *su, const void *ip, uint family);
extern bool axa_str_to_su(axa_socku_t *su, const char *str);
extern void axa_bits_to_mask(struct in6_addr *mask, int bits);
extern int axa_str_to_cidr(axa_emsg_t *emsg, axa_socku_t *su, const char *str);
extern bool axa_get_srvr(axa_emsg_t *emsg, const char *addr_port,
			 bool passive, struct addrinfo **resp);
extern bool axa_set_sock(axa_emsg_t *emsg, int s, const char *label,
			 bool nonblock);
extern bool axa_bind_tcp_listen(axa_emsg_t *emsg, axa_lsock_t *lsocks,
				uint *num_lsocks, uint max_lsocks,
				const char *addr_port);
extern bool axa_bind_unix_listen(axa_emsg_t *emsg, axa_lsock_t *lsocks,
				 uint *num_lsocks, uint max_lsocks,
				 const char *sname, mode_t mode,
				 uid_t uid, gid_t gid, axa_lsock_type_t type);


#endif /* AXA_SOCKET_H */
