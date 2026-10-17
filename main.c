#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#define IPBUF_LEN 16
#define DEF_PKT_LEN 60
#define MIN_PKT_LEN 28
#define MAX_PKT_LEN 65000
#define HDR_IPV4_LEN 20

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
#define ERR_TO_BIG_IPV4(s) \
    fprintf(stderr, "too big ipv4 `%s` specified\n", s)
#define ERR_TOO_BIG_PKT(s) \
    fprintf(stderr, "too big packetlen `%s` specified\n", s);
#define ERR_EXTRA_ARG(s, n) \
    fprintf(stderr, "Extra arg `%s` (position %d, argc %d)\n", s, n, n);
#define ERR_HANDLE_PKT_LEN(s, n) \
    fprintf(stderr, "Cannot handle \"packetlen\" cmdline arg `%s` on position %d (argc %d)\n", s, n, n);
#define INVALID_IPV4(s) \
    fprintf(stderr, "Not a IPv4 address `%s`\n", s);
#define INVALID_HDR_SIZE(n) \
    fprintf(stderr, "Malformation of IP header size `%d`\n", n);
#define CREATION_SOCKET_FAILED \
    fprintf(stderr, "Socket creation failed\n");
#define BINDING_SOCKET_FAILED \
    fprintf(stderr, "Socket binding failed\n");

typedef struct s_in {
    struct sockaddr_in ipv4[STACK_INIT];
    size_t pkt_len;
} t_in;

typedef struct __attribute__((packed)) {
    uint8_t version : 4; // IPV4
	uint8_t header_len : 4;
	uint8_t type_service;
	uint16_t total_len;
    uint16_t id;
	uint16_t fragment_offset;
    uint8_t ttl;
    uint8_t protocol;
    uint16_t protocol_checksum;
    uint32_t src_addr;
    uint32_t dst_addr;
} t_ip_pkt;

/* traceroute <ip> <size> */

/* affiche la liste des routeurs que
    traverse un paquet
    pour arriver jusqu’à l’IP,
    avec le temps de réponse de chacun. */

/*<size> fixe la taille totale du paquet
    envoyé (en-têtes IP + UDP + données).*/

/* TTL par paquet (TIME TO LIVE)*/

void init(t_in *in) {
    memset(&in->ipv4, 0, sizeof(in->ipv4));
    in->ipv4->sin_family = AF_INET;
    in->pkt_len = 0;
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
    char tmp[IPBUF_LEN];
    if (strlen(args[0]) >= IPBUF_LEN) {
        ERR_TO_BIG_IPV4(args[0]);
        return WRONG;
    }
    strncpy(tmp, args[0], IPBUF_LEN - 1);
    tmp[IPBUF_LEN] = '\0';
    if (!(inet_pton(in->ipv4->sin_family, tmp, &in->ipv4->sin_addr))) {
        INVALID_IPV4(tmp);
        return WRONG;
    }
    if (n_args == 2) {
        in->pkt_len = atoi(args[1]);
        if (in->pkt_len == ATOI_ERROR) {
            ERR_HANDLE_PKT_LEN(args[1], MAX_PARSING - 1)
            return WRONG;
        }
    }
    else {
        in->pkt_len = DEF_PKT_LEN; 
    }
    return CORRECT;
}

int
build_pkt(t_in *in, t_ip_pkt *pkt) {
    if (sizeof(t_ip_pkt) != HDR_IPV4_LEN) {
        INVALID_HDR_SIZE((int)sizeof(t_ip_pkt));
        return WRONG;
    }
    pkt->dst_addr = ntohl(in->ipv4->sin_addr.s_addr);
    pkt->ttl = 0;
    pkt->version >> 4;
    return CORRECT;
}

int opn_sock(t_in *in) {
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) {
        CREATION_SOCKET_FAILED;
        return WRONG;
    }
    if (bind(fd, (const struct sockaddr*)&in->ipv4, sizeof(in->ipv4)) < 0) {
        close(fd);
        BINDING_SOCKET_FAILED;
        return WRONG;
    }
    return fd;
}

int 
main(int n_args, char **args) {
    t_in in[STACK_INIT];
    init(in);
    if (n_args == MIN_PARSING) {
        USAGE;
        return CORRECT;
    }
    if (parse_args((size_t)n_args - 1, args + 1, in) == WRONG) {
        return WRONG;
    }
    t_ip_pkt pkt[STACK_INIT];
    if (build_pkt(in, pkt) == WRONG) {
        return WRONG;
    }
    return CORRECT;
}