#define _GNU_SOURCE
#include "../hdrs/impl.h"

int
get_addr(t_in *in)
{
    struct addrinfo hints, *res = NULL;

    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_DGRAM;
    hints.ai_flags |= AI_IDN;

    if (getaddrinfo(in->saddr, NULL, &hints, &res) || res == NULL) {
        INVALID_IPV4(in->saddr);
        return WRONG;
    }
    memcpy(in->iaddr, res->ai_addr, sizeof(struct sockaddr_in));
    in->iaddr->sin_port = htons(UDP_PORT);
    in->dst_port = UDP_PORT;
    inet_ntop(AF_INET, &(in->iaddr->sin_addr), in->saddr, sizeof(in->saddr));
    freeaddrinfo(res);
    return CORRECT;
}

int
parse_args(size_t n_args, char **args, t_in *in)
{
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
    if (strlen(args[0]) >= INET_ADDRSTRLEN) {
        ERR_TO_BIG_IPV4(args[0]);
        return WRONG;
    }
    snprintf(in->saddr, sizeof(in->saddr), "%s", args[0]);
    if (get_addr(in) == WRONG) {
        return WRONG;
    }
    if (n_args == 2) {
        int v = atoi(args[1]);
        if (v <= 0) {
            ERR_HANDLE_PKT_LEN(args[1], MAX_PARSING - 1);
            return WRONG;
        }
        if (v < MIN_PKT_LEN) v = MIN_PKT_LEN;
        if (v > MAX_PKT_LEN) v = MAX_PKT_LEN;
        in->lpkt = (int)v;
    }
    else {
        in->lpkt = DEF_PKT_LEN;
    }
    return CORRECT;
}

int
opn_sock(int *fds, t_in *in)
{
    fds[FD_SEND] = socket(AF_INET, SOCK_DGRAM, 0);
    if (fds[FD_SEND] < 0) {
        CREATION_SOCKET_SEND_FAILED;
        return WRONG;
    }
    fds[FD_RECV] = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
    if (fds[FD_RECV] < 0) {
        close_fds(fds);
        CREATION_SOCKET_RECV_FAILED;
        return WRONG;
    }
    struct sockaddr_in me;
    socklen_t len = sizeof(me);
    memset(&me, 0, sizeof(me));
    me.sin_family = AF_INET;
    if (bind(fds[FD_SEND], (struct sockaddr *)&me, sizeof(me)) < 0
        || getsockname(fds[FD_SEND], (struct sockaddr *)&me, &len) < 0) {
        close_fds(fds);
        return WRONG;
    }
    in->src_port = me.sin_port;
    return CORRECT;
}

int
send_pkt(int *fds, t_in *in, void *buf, size_t lbuf)
{
    in->iaddr->sin_port = htons(in->dst_port);
    ssize_t r = sendto(fds[FD_SEND], buf, lbuf, 0,
                       (struct sockaddr *)in->iaddr,
                       sizeof(struct sockaddr_in));
    if (r < 0) {
        close_fds(fds);
        SENDTO_FAILED;
        return WRONG;
    }
    return CORRECT;
}

int
handle_reply(const uint8_t *buf, size_t r, t_in *in)
{
    if (r < sizeof(struct iphdr))
        return 0;
    const struct iphdr *ip = (const struct iphdr *)buf;
    size_t iplen = (size_t)ip->ihl * 4;
    if (ip->protocol != IPPROTO_ICMP || iplen < sizeof(struct iphdr)
        || r < iplen + sizeof(struct icmphdr) + sizeof(struct iphdr))
        return 0;

    const struct icmphdr *icmp = (const struct icmphdr *)(buf + iplen);
    int ttl_exceeded = (icmp->type == ICMP_TIME_EXCEEDED && icmp->code == 0);
    int dest_unreach = (icmp->type == ICMP_DEST_UNREACH);
    if (!ttl_exceeded && !dest_unreach)
        return 0;

    const struct iphdr *inner =
        (const struct iphdr *)((const uint8_t *)icmp + sizeof(struct icmphdr));
    size_t innerlen = (size_t)inner->ihl * 4;
    if (innerlen < sizeof(struct iphdr)
        || r < iplen + sizeof(struct icmphdr) + innerlen + sizeof(struct udphdr))
        return 0;
    if (inner->protocol != IPPROTO_UDP
        || inner->daddr != in->iaddr->sin_addr.s_addr)
        return 0;

    const struct udphdr *udp =
        (const struct udphdr *)((const uint8_t *)inner + innerlen);
    if (udp->uh_sport != in->src_port || udp->uh_dport != htons(in->dst_port))
        return 0;

    inet_ntop(AF_INET, &ip->saddr, in->waiting_addr, sizeof(in->waiting_addr));
    struct hostent *host = gethostbyaddr(&ip->saddr, sizeof(ip->saddr), AF_INET);
    snprintf(in->waiting_host, sizeof(in->waiting_host), "%s",
             host ? host->h_name : in->waiting_addr);
    if (dest_unreach)
        in->stop = 1;
    return 1;
}

int
recv_pkt(int *fds, t_in *in, void *buf, size_t lbuf)
{
    struct timeval tv = { .tv_sec = 0, .tv_usec = 25000 };

    in->waiting_addr[0] = '\0';
    in->waiting_host[0] = '\0';

    for (;;) {
        fd_set rfds;
        FD_ZERO(&rfds);
        FD_SET(fds[FD_RECV], &rfds);

        int ret = select(fds[FD_RECV] + 1, &rfds, NULL, NULL, &tv);
        if (ret < 0) {
            close_fds(fds);
            SELECT_FAILED;
            return WRONG;
        }
        if (ret == 0)
            return TIMEOUT;

        ssize_t r = recvfrom(fds[FD_RECV], buf, lbuf, 0, NULL, NULL);
        if (r < 0) {
            close_fds(fds);
            RECVFROM_FAILED;
            return WRONG;
        }
        if (handle_reply((const uint8_t *)buf, (size_t)r, in)) {
            return CORRECT;
        }       
    }
}