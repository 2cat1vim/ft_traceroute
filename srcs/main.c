#include "../hdrs/impl.h"

int 
main(int n_args, char **args) 
{
    uid_t uid = getuid();
    if (uid != 0) {
        ERR_SUDO(uid);
        return WRONG;
    }
    t_in in[STACK_INIT];
    memset(&in->iaddr, 0, sizeof(in->iaddr));
    in->iaddr->sin_family = AF_INET;
    in->lpkt = 0;
    in->stop = 0;
    in->cat_hops = 0;
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
    for (in->ttl = 1; in->ttl <= MAX_TTL; in->ttl++) {
        if (in->ttl == 1) {
            TRACEROUTE_HEADER(args[1], in->saddr, HOPE, in->lpkt);
        }
        if (setsockopt(fds[FD_SEND], IPPROTO_IP, IP_TTL,
                   &in->ttl, sizeof(in->ttl)) == -1) {
            TTL_FAILED;
            return WRONG;
        }
        for (int hope = 0; hope < HOPE; hope++) {
            char last_addr[INET_ADDRSTRLEN];
            strcpy(last_addr, in->waiting_addr);
            if (send_pkt(fds, in, sdr_buf, sizeof(sdr_buf)) == WRONG) {
                return WRONG;
            }
            uint8_t rcv_buf[PKT_LBUF];
            if (recv_pkt(hope, fds, in, rcv_buf, sizeof(rcv_buf)) == WRONG) {
                return WRONG;
            }
            if (strcmp(last_addr, in->waiting_addr) != 0) {
                printf("%d %s (%s)\n", in->ttl, in->waiting_host, in->waiting_addr);
            }
            if (in->stop == 1) {
                close_fds(fds);
                return CORRECT;
            }
        }
    }
    close_fds(fds);
    return CORRECT;
}