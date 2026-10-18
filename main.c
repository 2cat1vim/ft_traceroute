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

#define IPBUF_LEN 16
#define DEF_PKT_LEN 60
#define MIN_PKT_LEN 28
#define MAX_PKT_LEN 65000
#define HDR_IPV4_LEN 20
#define PKT_LBUF 64

#define UDP_PORT 33434
#define MAX_TTL 64
#define PROBES_PER_HOPE 3

#define FD_SEND 0
#define FD_RECV 1
#define LFDS 2

#define STACK_INIT 1

#define HELP_FLAG "--help"

#define MAX_PARSING 3
#define MIN_PARSING 1

#define CORRECT 0
#define WRONG 1

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


typedef struct s_in {
    struct sockaddr_in iaddr[STACK_INIT];
    size_t laddr;
    char saddr[IPBUF_LEN];
    int lpkt;
} t_in;

/* traceroute <ip> <size> */

/* affiche la liste des routeurs que
    traverse un paquet
    pour arriver jusqu’à l’IP,
    avec le temps de réponse de chacun. */

/*<size> fixe la taille totale du paquet
    envoyé (en-têtes IP + UDP + données).*/

/* TTL par paquet (TIME TO LIVE)*/

void 
init(t_in *in) {
    memset(&in->iaddr, 0, sizeof(in->iaddr));
    in->iaddr->sin_family = AF_INET;
    in->lpkt = 0;
}

void 
debug(t_in *in) {
    printf("iaddr->sin_addr.s_addr: %d\nladdr: %ld\nsaddr: %s\npkt_len: %d\n", 
        in->iaddr->sin_addr.s_addr,
        in->laddr,
        in->saddr,
        in->lpkt);
}

int
get_addr(t_in *in)
{
    struct addrinfo hints, *res;
    
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_INET;
    hints.ai_flags = AI_CANONNAME;
    hints.ai_flags |= AI_IDN;

    int rc = getaddrinfo(in->saddr, NULL, &hints, &res);
    if (rc) {
        INVALID_IPV4(in->saddr);
        return WRONG;
    }
    
    in->laddr = res->ai_addrlen;
    memcpy(in->iaddr, res->ai_addr, sizeof(struct sockaddr_in));
    in->iaddr->sin_port = htons(UDP_PORT + (MAX_TTL * PROBES_PER_HOPE - 1));
    inet_ntop(AF_INET, &(in->iaddr->sin_addr), in->saddr, in->laddr);
    freeaddrinfo(res);
    return CORRECT;
}

int
parse_args(size_t n_args, char **args, t_in *in) {
    for (size_t i = 0; i < n_args; i++) {
        if (strcmp(args[i], HELP_FLAG) == CORRECT) {
            USAGE;
            return WRONG;
        }
    }
    if (n_args >= MAX_PARSING) {
        ERR_EXTRA_ARG(args[MAX_PARSING - 1], MAX_PARSING);
        return WRONG;
    }
    if (strlen(args[0]) >= IPBUF_LEN) {
        ERR_TO_BIG_IPV4(args[0]);
        return WRONG;
    }
    strncpy(in->saddr, args[0], IPBUF_LEN - 1);
    in->saddr[IPBUF_LEN] = '\0';
    if (get_addr(in) == WRONG) {
        return WRONG;
    }
    if (n_args == 2) {
        in->lpkt = atoi(args[1]);
        if (in->lpkt <= ATOI_ERROR) {
            ERR_HANDLE_PKT_LEN(args[1], MAX_PARSING - 1)
            return WRONG;
        }
        if (in->lpkt < MIN_PKT_LEN) {
            in->lpkt = MIN_PKT_LEN;
        }
        if (in->lpkt > MAX_PKT_LEN) {
            in->lpkt = MAX_PKT_LEN;
        }
    }
    else {
        in->lpkt = DEF_PKT_LEN; 
    }
    return CORRECT;
}

int
build_pkt(t_in *in, void *buf, size_t lbuf) {
    memset(buf, 0, lbuf);
    struct iphdr *ip = (struct iphdr *)buf;
    ip->daddr = in->iaddr->sin_addr.s_addr;
    ip->version = 4;
    ip->ihl = 5;
    ip->protocol = IPPROTO_UDP;
    ip->ttl = MAX_TTL;
    ip->tot_len = htons(lbuf);
    return CORRECT;
}

void 
close_fds(int *fd) {
    for (size_t i = 0; i < 2; i++) {
        if (fd[i] != -1) {
            close(fd[i]);
        }
    }
}

int 
opn_sock(int *fds) {
    fds[FD_SEND] = socket(AF_INET, SOCK_DGRAM, 0);
    if (fds[FD_SEND] < 0) {
        CREATION_SOCKET_SEND_FAILED;
        return WRONG;
    }
    fds[FD_RECV] = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
    if (fds[FD_RECV] < 0) {
        CREATION_SOCKET_RECV_FAILED;
        return WRONG;
    }
    return CORRECT;
}

int 
send_pkt(int *fds, t_in *in, void *buf, size_t lbuf) {
    ssize_t r = sendto(fds[FD_SEND], buf, lbuf, 0,
            (struct sockaddr*)&in->iaddr,
            sizeof(struct sockaddr_in));
    if (r < 0) {
        close_fds(fds);
        SENDTO_FAILED;
        return (WRONG);
    }
    return (CORRECT);
}

int 
recv_pkt(int *fds, t_in *in, void *buf, size_t lbuf) {
    socklen_t l = sizeof(in->iaddr);

    fd_set rfds;
    struct timeval tv = { .tv_sec = 1, .tv_usec = 0 };

    FD_ZERO(&rfds);
    FD_SET(fds[1], &rfds);

    int ret = select(fds[1] + 1, &rfds, NULL, NULL, &tv);
    if (ret < 0) {
        SELECT_FAILED;
    }
    else if (ret == 0) {
        RECVFROM_TIMEOUT(in->saddr);
    }
    else if (FD_ISSET(fds[1], &rfds)) {
        ssize_t r = recvfrom(fds[FD_RECV], buf, lbuf, 0, (struct sockaddr*)&in->iaddr->sin_addr.s_addr, &l);
        if (r < 0) {
            close_fds(fds);
            RECVFROM_FAILED;
            return (WRONG);
        }
    }
    struct icmphdr *icmp = (struct icmphdr*)(buf);
    char str[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &(icmp->un.gateway), str, sizeof(str));
    printf("Reply gateway: %s\n", str);
    return (CORRECT);
}

int 
main(int n_args, char **args) {
    uid_t uid = getuid();
    if (uid != 0) {
        ERR_SUDO(uid);
        return WRONG;
    }
    t_in in[STACK_INIT];
    init(in);
    if (n_args == MIN_PARSING) {
        USAGE;
        return CORRECT;
    }
    if (parse_args((size_t)n_args - 1, args + 1, in) == WRONG) {
        return WRONG;
    }
    uint8_t sdr_buf[PKT_LBUF];
    if (build_pkt(in, sdr_buf, sizeof(sdr_buf)) == WRONG) {
        return WRONG;
    }
    int fds[LFDS] = {-1, -1};
    if (opn_sock(fds) == WRONG) {
        return WRONG;
    }
    debug(in);
    if (send_pkt(fds, in, sdr_buf, sizeof(sdr_buf)) == WRONG) {
        return WRONG;
    }
    uint8_t rcv_buf[PKT_LBUF];
    if (recv_pkt(fds, in, rcv_buf, sizeof(rcv_buf)) == WRONG) {
        return WRONG;
    }
    close_fds(fds);
    return CORRECT;
}