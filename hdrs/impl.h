#ifndef IMPL_H
#define IMPL_H
#define _GNU_SOURCE
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netinet/ip.h>
#include <netdb.h>
#include <netinet/ip_icmp.h>
#include <netinet/udp.h>

#define IPBUF_LEN 16
#define DEF_PKT_LEN 60
#define MIN_PKT_LEN 28
#define MAX_PKT_LEN 65000
#define HDR_IPV4_LEN 20
#define PKT_LBUF 64

#define UDP_PORT 33434
#define MAX_TTL 30
#define HOPE 3

#define FD_SEND 0
#define FD_RECV 1
#define LFDS 2

#define STACK_INIT 1

#define HELP_FLAG "--help"

#define MAX_PARSING 3
#define MIN_PARSING 1

#define CORRECT 0
#define WRONG 1
#define TIMEOUT 2

#define ATOI_ERROR 0

#define USAGE \
    fprintf(stdout, "Usage:\n" \
                    "   ft_traceroute host [ packet len ]\n" \
                    "Options:\n" \
                    "   --help  Read this help and exit\n" \
                    "\nArguments:\n" \
                    "+      host        The host to trace route to\n" \
                    "       packetlen   The full packet length (default is the length of an IP\n" \
                    "                   header plus 40). Can be ignored or increased to a minimal\n" \
                    "                   allowed value\n");
#define TRACEROUTE_HEADER(s, ss, n, nn) \
    fprintf(stdout, "ft_traceroute to %s (%s), %d hops max, %d byte packets\n", s, ss, n, nn);
#define ERR_SUDO(u) \
    fprintf(stderr, "uid `%d` is not 0\n", u);  
#define ERR_TO_BIG_IPV4(s) \
    fprintf(stderr, "too big ipv4 `%s` specified\n", s)
#define ERR_TOO_BIG_PKT(s) \
    fprintf(stderr, "too big packetlen `%s` specified\n", s);
#define ERR_EXTRA_ARG(s, n) \
    fprintf(stderr, "Extra arg `%s` (position %d, argc %d)\n", s, n, n);
#define ERR_HANDLE_PKT_LEN(s, n) \
    fprintf(stderr, "Cannot handle \"packetlen\" cmdline arg `%s` on position %d (argc %d)\n", s, n, n);
#define INVALID_IPV4(s) \
    fprintf(stderr, "Unknown host `%s`\n", s);
#define CREATION_SOCKET_SEND_FAILED \
    fprintf(stderr, "Socket send creation failed\n");
#define CREATION_SOCKET_RECV_FAILED \
    fprintf(stderr, "Socket recv creation failed\n")
#define BINDING_SOCKET_FAILED \
    fprintf(stderr, "Socket binding failed\n");
#define SENDTO_FAILED \
    fprintf(stderr, "Sendto failed\n");
#define RECVFROM_FAILED \
    fprintf(stderr, "Recvfrom failed\n");
#define RECVFROM_TIMEOUT(s) \
    fprintf(stderr, "Recvfrom timeout `%s`\n", s);
#define SELECT_FAILED \
    fprintf(stderr, "Select failed\n");
#define TTL_FAILED \
    fprintf(stderr, "TTL failed\n");
#define HOST_FAILED \
    fprintf(stderr, "Gethostbyaddr failed")

typedef struct s_in {
    struct sockaddr_in iaddr[STACK_INIT];
    in_port_t src_port;
    in_port_t dst_port;
    size_t laddr;
    char saddr[IPBUF_LEN];
    int lpkt;
    int ttl;
    int stop;
    char waiting_addr[INET_ADDRSTRLEN];
    char waiting_host[64];
} t_in;

int get_addr(t_in *in);
int parse_args(size_t n_args, char **args, t_in *in);
int build_pkt(t_in *in, void *buf, size_t lbuf);
int  opn_sock(int *fds, t_in *in);
int send_pkt(int *fds, t_in *in, void *buf, size_t lbuf);
int handle_reply(const uint8_t *buf, size_t r, t_in *in);
int recv_pkt(int *fds, t_in *in, void *buf, size_t lbuf);
void close_fds(int *fd);
void debug(t_in *in);

#endif