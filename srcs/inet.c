#include "../hdrs/impl.h"

int
get_addr(t_in *in)
{
    struct addrinfo hints, *res;
    
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_INET;
    hints.ai_flags |= AI_IDN;

    if (getaddrinfo(in->saddr, NULL, &hints, &res)) {
        INVALID_IPV4(in->saddr);
        return WRONG;
    }
    
    in->laddr = res->ai_addrlen;
    memcpy(in->iaddr, res->ai_addr, sizeof(struct sockaddr_in));
    in->iaddr->sin_port = htons(UDP_PORT + (MAX_TTL * HOPE - 1));
    inet_ntop(AF_INET, &(in->iaddr->sin_addr), in->saddr, in->laddr);
    freeaddrinfo(res);
    return CORRECT;
}

int
parse_args(size_t n_args, char **args,
                             t_in *in) 
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
    strncpy(in->saddr, args[0], INET_ADDRSTRLEN - 1);
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
opn_sock(int *fds)
{
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
send_pkt(int *fds, t_in *in, 
               void    *buf, 
               size_t  lbuf)
{
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

/*
** ICMP REPLIES IN UDP TRACEROUTE (IPv4)
**
** ICMP Type 11, Code 0:
**     Time Exceeded (TTL expired in transit).
**     -> An intermediate router responded.
**     -> Print the router's source IP and RTT.
**     -> Continue to the next probe / TTL.
**
** ICMP Type 3, Code 3:
**     Destination Unreachable (Port Unreachable).
**     -> Usually means the UDP probe reached the destination.
**     -> Verify that the reply matches our probe and comes from
**        the target IP before considering the destination reached.
**     -> Print the result and stop the traceroute.
**
** ICMP Type 3, Code 0:
**     Network Unreachable.
**     -> The destination network cannot be reached.
**     -> Report the error; usually stop the traceroute.
**
** ICMP Type 3, Code 1:
**     Host Unreachable.
**     -> The destination host cannot be reached.
**     -> Report the error; usually stop the traceroute.
**
** ICMP Type 3, Code 9, 10 or 13:
**     Administratively prohibited (filtering).
**     -> Report that the probe is blocked.
**     -> Usually stop or mark the destination as unreachable.
**
** TIMEOUT:
**     No valid response arrived before the timeout.
**     -> Print '*' for this probe.
**     -> Continue with the remaining probes and next TTL.
**
** OTHER ICMP RESPONSES:
**     -> Interpret according to their type and code.
**     -> Do not automatically treat them as success.
**
** STOP CONDITIONS:
**     1. Destination reached and a valid response confirms it.
**     2. A terminal network error is detected and handled.
**     3. MAX_TTL is reached.
**
** IMPORTANT:
**     - TTL starts at 1, not 0.
**     - Set IP_TTL before sending probes for each hop.
**     - Send PROBES_PER_HOP probes with the same TTL.
**     - Read the outer IPv4 source IP to identify the responder.
**     - Validate the ICMP response and match it to our probe.
**     - A timeout does not mean the router does not exist.
*/
void 
handle_reply(struct iphdr *ip, struct icmphdr *icmp, t_in *in)
{
    int ttl_exceeded = (icmp->type == 11 && icmp->code == 0);
    int dest_unreach  = (icmp->type == 3 && (icmp->code == 3
                                          || icmp->code == 1
                                          || icmp->code == 0));
    if (!ttl_exceeded && !dest_unreach)
        return ;
    char tmp[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &(ip->saddr), tmp, sizeof(tmp));
    strcpy(in->waiting_addr, tmp);
    struct hostent *host = gethostbyaddr(&ip->saddr, sizeof(ip->saddr), AF_INET);
    if (!host) {
        strcpy(in->waiting_host, tmp);
    }
    else {
        strcpy(in->waiting_host, host->h_name);
    }
    if (dest_unreach) {
        in->stop = 1;
    }
}

int 
recv_pkt(int hope, int *fds,
                t_in    *in,
                void    *buf,
                size_t  lbuf)
{
    fd_set rfds;
    struct timeval tv = { .tv_sec = 0, .tv_usec = 50000 };

    FD_ZERO(&rfds);
    FD_SET(fds[1], &rfds);

    int ret = select(fds[1] + 1, &rfds, NULL, NULL, &tv);
    if (ret < 0) {
        SELECT_FAILED;
    }
    else if (ret == 0) {
        in->cat_hops++;
        if (in->cat_hops > MAX_HOPE) {
            in->stop = 1;
            return CORRECT;
        }
        if (hope == 0) {
            fprintf(stdout, "%d * * *\n", in->ttl);
        }
    }
    else if (FD_ISSET(fds[1], &rfds)) {
        ssize_t r = recvfrom(
            fds[FD_RECV],
            buf,
            lbuf,
            0, 
            NULL,
            NULL);
        if (r < 0) {
            close_fds(fds);
            RECVFROM_FAILED;
            return (WRONG);
        }
    }
    struct iphdr *ip = (struct iphdr*)(buf);
    struct icmphdr *icmp = (struct icmphdr*)(buf + ip->ihl * 4);
    handle_reply(ip, icmp, in);
    return (CORRECT);
}