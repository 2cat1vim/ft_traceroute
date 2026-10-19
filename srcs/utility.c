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
