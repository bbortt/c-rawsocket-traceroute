/**
 * Licensed under the terms of the Apache 2.0 License.
 * Visit: https://www.apache.org/licenses/LICENSE-2.0.html.
 *
 * @author Timon Borter
 */
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include <ifaddrs.h>

#include <netdb.h>
#include <arpa/inet.h>

#include <sys/types.h>
#include <sys/socket.h>
#include <limits.h>

#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <netinet/udp.h>

#include "crc.c"

#define MAX_HOPS 30
#define IP_IDENTIFICATION 12345

struct trace_span {
    uint8_t ttl;
    struct in_addr *src;
    struct in_addr *dest;
};

int get_if_addr(const char *if_name, struct in_addr *src) {
    printf("using networking interface %s\n", if_name);

    struct ifaddrs *addrs;
    getifaddrs(&addrs);
    struct ifaddrs *next_addr = addrs;
    while (next_addr) {
        if (next_addr->ifa_addr && next_addr->ifa_addr->sa_family == AF_INET) {
            struct sockaddr_in *if_addr = (struct sockaddr_in *) next_addr->ifa_addr;
            if (0 == strcmp(next_addr->ifa_name, if_name)) {
                memcpy(src, &if_addr->sin_addr, sizeof(struct in_addr));
                freeifaddrs(addrs);
                return 0;
            }
        }

        next_addr = next_addr->ifa_next;
    }

    return -1;
}

int get_eth0_addr(struct in_addr *src) {
    return get_if_addr("eth0", src);
}

int hostname_to_ip(char *hostname, struct in_addr *dest) {
    struct hostent *he;
    struct in_addr **addr_list;

    if ((he = gethostbyname(hostname)) == NULL) {
        return -1;
    }

    addr_list = (struct in_addr **) he->h_addr_list;

    for (unsigned int i = 0; addr_list[i] != NULL; i++) {
        // return the first one;
        *dest = *addr_list[i];
        return 0;
    }

    return -1;
}

char *build_span(const struct trace_span *span) {
    // build packet
    char *packet = malloc(sizeof(struct iphdr) + sizeof(struct icmphdr) + sizeof(struct udphdr));

    // IP header
    struct iphdr *iph = (struct iphdr *) packet;
    // ICMP header, points to the end of the ip header
    struct icmphdr *icmphd = (struct icmphdr *) (packet + sizeof(struct iphdr));

    // create IP header
    iph->ihl = 5;
    iph->version = 4;
    iph->tos = 0;
    iph->tot_len = sizeof(struct iphdr) + sizeof(struct icmphdr);
    iph->id = htons(IP_IDENTIFICATION);
    iph->frag_off = 0;
    iph->ttl = span->ttl;
    iph->protocol = IPPROTO_ICMP;
    iph->saddr = (uint32_t) span->src->s_addr;
    iph->daddr = (uint32_t) span->dest->s_addr;
    iph->check = 0;

    // create ICMP header
    icmphd->type = ICMP_ECHO;
    icmphd->code = 0;
    icmphd->checksum = 0;
    icmphd->checksum = GNUNET_CRYPTO_crc16_n((unsigned short *) (packet + sizeof(struct iphdr)),
                                             sizeof(struct icmphdr));

    // calculate full checksum
    iph->check = GNUNET_CRYPTO_crc16_n((unsigned short *) packet, sizeof(struct iphdr) + sizeof(struct icmphdr));

    // create UDP header
    struct udphdr *udp = (struct udphdr *) (packet + sizeof(struct iphdr) + sizeof(struct icmphdr));
    udp->source = htons(50000);
    udp->dest = (63000);
    udp->len = htons(8);
    udp->check = 0;
    udp->check = GNUNET_CRYPTO_crc16_n((unsigned short *) (packet + sizeof(struct iphdr) + sizeof(struct icmphdr)),
                                       sizeof(struct udphdr));

    return packet;
}

int trace(int out_sock, int in_sock, struct in_addr *src, struct in_addr *dest) {
    // build traceroute span
    struct trace_span span;
    span.src = src;
    span.dest = dest;

    // destination socket address
    struct sockaddr_in dest_sockaddr;
    dest_sockaddr.sin_family = AF_INET;
    dest_sockaddr.sin_addr.s_addr = dest->s_addr;
    dest_sockaddr.sin_port = htons(80);

    // initialize ignored hop count for localhosts
    uint8_t ignored = 0;

    // initialize ip (hop) lookup struct
    struct sockaddr_in h_lkp;
    memset(&h_lkp, 0, sizeof(h_lkp));
    h_lkp.sin_family = AF_INET;

    for (uint8_t i = 0; i < MAX_HOPS; i++) {
        // upgrade span, create packet
        span.ttl = i + 1;
        char *packet = build_span(&span);

        // send span
        ssize_t dat = sendto(out_sock, packet, sizeof(struct iphdr) + sizeof(struct icmphdr) + sizeof(struct udphdr), 0,
                             (struct sockaddr *) &dest_sockaddr, sizeof dest_sockaddr);

        // free assigned packet memory
        free(packet);

        // receive answer
        struct sockaddr_in receiver;
        socklen_t sockaddr_size = sizeof(receiver);
        char buf[sizeof(struct iphdr) + sizeof(struct icmphdr)];
        recvfrom(in_sock, buf, sizeof(struct iphdr) + sizeof(struct icmphdr), 0, (struct sockaddr *) &receiver,
                 &sockaddr_size);
        struct iphdr *ip = (struct iphdr *) buf;
        struct icmphdr *icmp = (struct icmphdr *) (buf + sizeof(struct iphdr));

        // "translate" response ip
        char res_ip[15];
        inet_ntop(AF_INET, &ip->saddr, res_ip, sizeof(res_ip));

        // check loopback resolves, ignore "hop"
        if (0 == strcmp((char *) &res_ip, "127.0.0.1")) {
            ignored++;
            continue;
        }

        // lookup hostname by response ip
        h_lkp.sin_addr.s_addr = ip->saddr;

        static char hostname[64];
        if (0 != getnameinfo((struct sockaddr *) &h_lkp, sizeof(h_lkp), hostname, sizeof(hostname), NULL, 0, 0)) {
            strcpy(hostname, "*");
        }

        // print span
        printf("hop %d - [%s]: %s\n", span.ttl - ignored, hostname, res_ip);

        // check for trace completion, terminate loop
        if (0 == memcmp(&dest, &ip->saddr, sizeof(struct in_addr))) {
            printf("trace completed!\n");
            return 0;
        }
    }

    fprintf(stderr, "unable to complete trace in %d hops!\n", MAX_HOPS);

    return 1;
}

int main(int argc, char **argv) {
    // argument check
    if (argc < 2) {
        fprintf(stderr, "illegal use of traceroute: ./traceroute [DESTINATION_DOMAIN] [NETWORKING_INTERFACE=eth0].\n");
        return 1;
    }

    // read src address from networking interface `eth0`
    struct in_addr src;
    int src_check = -1;
    if (argc != 3) {
        src_check = get_eth0_addr(&src);
    } else {
        src_check = get_if_addr(argv[2], &src);
    }

    if (0 != src_check) {
        fprintf(stderr, "cannot find networking interface!\n");
        return 1;
    }

    // print readable src ip
    char if_ip[15];
    inet_ntop(AF_INET, &src, if_ip, sizeof(if_ip));
    printf("will fire from networking interface %s\n", if_ip);

    // check and resolve destination hostname
    char *hostname = argv[1];
    struct in_addr dest;

    if (0 != hostname_to_ip(hostname, &dest)) {
        fprintf(stderr, "unable to resolve destination host '%s'!\n", hostname);
        return 1;
    }

    char ip[15];
    strcpy(ip, inet_ntoa(dest));

    printf("tracing down '%s' on '%s'..\n", hostname, ip);

    // finally bind raw socket, OUTBOUND
    int on = 1; // include headers in the packet
    int out_sock = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
    if (0 > out_sock) {
        fprintf(stderr, "error creating raw out-socket!\n");
        return -1;
    }
    if (0 != setsockopt(out_sock, IPPROTO_IP, IP_HDRINCL, (const char *) &on, sizeof(on))) {
        fprintf(stderr, "error setting out-socket options!\n");
        return -1;
    }

    // bind raw socket, INBOUND
    int in_sock = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
    if (0 > in_sock) {
        fprintf(stderr, "error creating raw in-socket!\n");
        return -1;
    }
    if (0 != setsockopt(in_sock, IPPROTO_IP, IP_HDRINCL, (const char *) &on, sizeof(on))) {
        fprintf(stderr, "error setting in-socket options!\n");
        return -1;
    }

    trace(out_sock, in_sock, &src, &dest);
}
