#include "../hdrs/impl.h"

void 
close_fds(int *fd) 
{
    for (size_t i = 0; i < 2; i++) {
        if (fd[i] != -1) {
            close(fd[i]);
        }
    }
}

void 
debug(t_in *in) 
{
    printf("iaddr->sin_addr.s_addr: %d\nladdr: %ld\nsaddr: %s\npkt_len: %d\n", 
        in->iaddr->sin_addr.s_addr,
        in->laddr,
        in->saddr,
        in->lpkt);
}