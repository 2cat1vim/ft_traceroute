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
    if (n_args == MIN_PARSING) {
        USAGE;
        return CORRECT;
    }
    if (parse_args((size_t)n_args - 1, args + 1, in) == WRONG) {
        return WRONG;
    }
    uint8_t sdr_buf[in->lpkt];
    size_t payload = in->lpkt - (MIN_PKT_LEN);
    memset(sdr_buf, 0, payload);
    int fds[LFDS] = {-1, -1};
    if (opn_sock(fds, in) == WRONG) {
        return WRONG;
    }
    for (in->ttl = 1; in->ttl <= MAX_TTL; in->ttl++) {
        if (in->ttl == 1) {
            TRACEROUTE_HEADER(args[1], in->saddr, MAX_TTL, in->lpkt);
        }
        if (setsockopt(fds[FD_SEND], IPPROTO_IP, IP_TTL,
                   &in->ttl, sizeof(in->ttl)) == -1) {
            TTL_FAILED;
            return WRONG;
        }

        printf("%2d", in->ttl);
        char last_addr[INET_ADDRSTRLEN] = "";
        for (int hope = 0; hope < HOPE; hope++) {
            if (send_pkt(fds, in, sdr_buf, payload) == WRONG) {
                return WRONG;
            }
            uint8_t rcv_buf[PKT_LBUF];
            switch (recv_pkt(fds, in, rcv_buf, sizeof(rcv_buf))) {
                case WRONG:
                    return WRONG;
                case TIMEOUT:
                    printf(" *");
            }
            in->dst_port++;
            if (strcmp(last_addr, in->waiting_addr) != 0 && strlen(in->waiting_addr) > 1) {
                printf(" %s (%s)", in->waiting_host, in->waiting_addr);
                strcpy(last_addr, in->waiting_addr);
            }
            fflush(stdout);
        }
        printf("\n");

        if (in->stop == 1) {
            close_fds(fds);
            return CORRECT;
        }
    }
    close_fds(fds);
    return CORRECT;
}