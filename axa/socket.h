/*
 * Advanced Exchange Access (AXA) socket and IP address code
 *
 *  Copyright (c) 2014-2015 by Farsight Security, Inc.
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

/**
 *  AXA socket union
 *
 *  Holds socket endpoint state
 */
typedef union {
	struct sockaddr sa;		/**< sockaddr */
	struct sockaddr_in ipv4;	/**< sockaddr_in for IPv4 */
	struct sockaddr_in6 ipv6;	/**< sockaddr_in6 for IPv6 */
	struct sockaddr_un sun;		/**< sockaddr_un for Unix domain */
} axa_socku_t;

/** @cond */
#ifndef s6_addr32
#define s6_addr32 __u6_addr.__u6_addr32
#endif
/** @endcond */

#ifdef HAVE_SA_LEN
/** @cond */
#define AXA_SU_LEN(s) ((s)->sa.sa_len)
/** @endcond */
#else
/**
 *  Return the length of an axa_socku_t union
 *
 *  \param[in] s a pointer to a populated axa_socku_t structure
 *
 *  \return the size of socket union structure as determined by family, or -1
 *  if family is unrecognized
 */
#define AXA_SU_LEN(s) ({sa_family_t _family = (s)->sa.sa_family;	\
	(_family == AF_INET) ? (int)sizeof((s)->ipv4)			\
	: (_family == AF_INET6) ? (int)sizeof((s)->ipv6)		\
	: (_family == AF_UNIX) ? (int)(sizeof((s)->sun)			\
				       -sizeof((s)->sun.sun_path)	\
				       +strlen((s)->sun.sun_path))	\
	: -1;})
#endif

/**
 *  Return the port number of a axa_socku_t union
 *  L-value use IPv4 port number if sa_family is AF_UNSPEC.
 *
 *  \param[in] su a pointer to a populated axa_socku_t structure
 *
 *  \return the port number
 */
#define AXA_SU_PORT(su) (*((su)->sa.sa_family == AF_INET6		\
			   ? &(su)->ipv6.sin6_port			\
			   : &(su)->ipv4.sin_port))

/** interesting poll(2) flags for an input socket */
#define AXA_POLL_IN	(POLLIN | POLLRDNORM | POLLRDBAND | POLLPRI)
/** intersting poll(2) flags for an output socket */
#define AXA_POLL_OUT	(POLLOUT | POLLWRNORM | POLLWRBAND)
/** poll(2) flags for noticing disconnect */
#define AXA_POLL_OFF	(POLLERR | POLLHUP | POLLNVAL)


/**
 *  Tests for errors on UDP output that are not necessarily fatal.
 *	Some firewall filters or access control lists including IPFW say
 *	EACCES on hits,	so treat EACCES like unreachables.
 *
 *	\param[in] e errno
 *
 *  \retval 1 on an errno that corresponds to an error that should not be
 *  fatal
 *  \retval 0 on errno that should be fatal
 */
#define AXA_IGNORED_UDP_ERRNO(e) (e == ECONNREFUSED			\
				  || e == EHOSTUNREACH			\
				  || e == ENETUNREACH			\
				  || e == EHOSTDOWN			\
				  || e == ENETDOWN			\
				  || e == EACCES			\
				  || e == ENOBUFS)

/**
 *  Tests for non-errors during non-blocking connect().
 *
 *  \retval 1 on an errno that corresponds to a non-fatal error
 *  \retval 0 on errno that should be fatal
 */
#define AXA_CONN_WAIT_ERRORS() (errno == EAGAIN || errno == EINPROGRESS	\
				|| errno == EALREADY)

/** wait this long for a busy port */
#define AXA_ADDR_WAIT_IN_USE	5


/* socket.c */
/** maximum string needed to represent the contents of an axa_socku_t
 * INET6_ADDRSTRLEN+1+5+1 is xxxx:...:xxx/65535 */
#define AXA_SU_TO_STR_LEN dcl_max(INET6_ADDRSTRLEN+1+5+1,		\
				  sizeof(((axa_socku_t*)0)->sun.sun_path)+1)

/**
 *  Extract IP address and port information from AXA socket union into
 *  a string.
 *  The finished string will be of the format "[IP][separator char][PORT]".
 *  If the address family of su is unrecognized, the function will fail with
 *  AXA_FAIL().
 *
 *  \param[out] str a char buffer of size str_len that will contain the
 *  finished string
 *  \param[in] str_len length of str
 *  \param[in] portc char to separate the IP address and port such as '.' or '/'
 *  \param[in] su pointer to source axa_socku_t
 *
 *  \return the value of str
 */
extern char *axa_su_to_str(char *str, size_t str_len, char portc,
			   const axa_socku_t *su);
/**
 *  Populate an axa_socku_t union with a supplied IPv4 or IPv6 address
 *
 *  \param[out] su pointer to a axa_socku_t union
 *  \param[in] data pointer to wire-format IPv4 or IPv6 address
 *  \param[in] data_len size of data and so IPv4 vs. IPv6 indicator
 *
 *  \retval true success, su contains the IP address
 *  \retval false failure, data_len was unrecognized and su is filled with 0s
 */
extern bool axa_data_to_su(axa_socku_t *su, const void *data, size_t data_len);

/**
 *  Populate an axa_socku_t union with the supplied IPv4 or IPv6 address
 *
 *  \param[out] su pointer to a axa_socku_t union
 *  \param[in] ip pointer to wire-format IPv4 or IPv6 address
 *  \param[in] family address family, should be AF_INET or AF_INET6
 *
 *  \retval true success, su contains the IP address
 *  \retval false failure, family was unrecognized and su is filled with 0s
 */
extern bool axa_ip_to_su(axa_socku_t *su, const void *ip, uint family);

/**
 *  Get a socket address from a dotted quad or IPv6 string. The function will
 *  fail if the IPv4 or IPv6 strings are invalid.
 *
 *  \param[out] su pointer to a axa_socku_t union
 *  \param[in] str dotted quad or IPv6 string
 *
 *  \retval true success, su contains the IP address
 *  \retval false failure, the address string was invalid and su filled with 0s
 */
extern bool axa_str_to_su(axa_socku_t *su, const char *str);

/**
 *  Get an IP prefix mask
 *
 *  \param[out] mask IPv6 address
 *  \param[in] bits number of bits
 */
extern void axa_bits_to_mask(struct in6_addr *mask, int bits);

/**
 *  Get an IP address and netmask.
 *
 *  \param[out] emsg if something goes wrong, this will contain the reason
 *  \param[in] su pointer to a populated axa_socku_t union
 *  \param[in] str string containing IP address with CIDR mask
 *
 *  \return the number of bits in the CIDR mask or -1 on error
 */
extern int axa_str_to_cidr(axa_emsg_t *emsg, axa_socku_t *su, const char *str);

/**
 *  Parse a "hostname,port" string specifying an SRA or RAD server.
 *  If the boolean passive is true, the function sets AI_PASSIVE. As per
 *  getaddrinfo(3), this causes the resulting IP address to be optionally
 *  filled with INADDR_ANY (IPv4)or in6addr_any (IPv6) for a call to bind(2).
 *
 *  \param[out] emsg if something goes wrong, this will contain the reason
 *  \param[in] addr_port string of the format "hostname,port"
 *  \param[in] passive boolean, if true, enable AI_PASSIVE
 *  \param[out] resp pointer to address of struct addrinfo, results appear here
 *
 *  \retval true success, *resp will have the results
 *  \retval false parsing error, check emsg
 */
extern bool axa_get_srvr(axa_emsg_t *emsg, const char *addr_port,
			 bool passive, struct addrinfo **resp);

/**
 *  Set socket (or other communications file descriptor) options.
 *
 *  AXA has the option of using several communications primitives. Depending on
 *  network details and the user's whim, AXA may use:
 *      - Unix domain (unix:/foo/bar)
 *      - TCP  (tcp:10.0.0.1,123)
 *      - SSH  (ssh:10.0.0.1,123)
 *      - UDP  (udp:10.0.0.1,123)
 *      - NMSG over TCP (nmsg:tcp:10.0.0.1,123)
 *      - NMSG over UDP (nmsg:udp:10.0.0.1,123)
 *
 *  There are a handful of code paths that will require this function to be
 *  called, and they won't know ahead of time which of the above connection
 *  primitives was specified. The above alternatives need some the following:
 *      - close-on-exec (FD_CLOEXEC)
 *      - non-blocking (O_NONBLOCK, set if nonblock is true)
 *      - Nagle Algorithm disabled (TCP and SSH only)
 *      - TCP keepalives enabled (TCP and SSH only)
 *      - Broadcasting enabled (UDP to broadcast IP address only)
 *
 *  As such, #axa_set_sock() tries to do the right thing for the given
 *  primitive. However, on some platforms, this is a best effort service
 *  (notably OS X which does not support SO_PROTOCOL) and there may be
 *  spurious warnings when AXA attempts to set a socket option that is
 *  non-sequitor for the given primitive.
 *
 *  \param[out] emsg if something goes wrong, this will contain the reason
 *  \param[in] s socket or fd
 *  \param[in] label descriptive labal referring to s (usually an address)
 *  \param[in] nonblock boolean, if true, set O_NONBLOCK
 *
 *  \retval true success
 *  \retval false something went wrong, check emsg
 */
extern bool axa_set_sock(axa_emsg_t *emsg, int s, const char *label,
			 bool nonblock);

#endif /* AXA_SOCKET_H */
