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

#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <netinet/udp.h>

//#include <sys/cdefs.h>
//#include <sys/types.h>
//#include <linux/ip.h>

struct trace_span {
    uint8_t ttl;
    struct in_addr *src;
    struct in_addr *dest;
};

int get_if_addr(const char *if_name, struct in_addr *src) {
    printf("Using networking interface %s\n", if_name);

    struct ifaddrs *addrs;
    getifaddrs(&addrs);
    struct ifaddrs *tmp = addrs;
    while (tmp) {
        if (tmp->ifa_addr && tmp->ifa_addr->sa_family == AF_INET) {
            struct sockaddr_in *if_addr = (struct sockaddr_in *) tmp->ifa_addr;
            if (0 == strcmp(tmp->ifa_name, if_name)) {
                memcpy(src, inet_ntoa(if_addr->sin_addr), sizeof(struct in_addr));
                freeifaddrs(addrs);
                return 0;
            }
        }

        tmp = tmp->ifa_next;
    }

    freeifaddrs(addrs);
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
        //Return the first one;
        *dest = *addr_list[i];
        return 0;
    }

    return -1;
}

int16_t calc_checksum(const uint16_t *data, unsigned int bytes) {
    uint32_t sum = 0;
    for (unsigned int i = 0; i < bytes / 2; i++)
        sum += data[i];
    sum = (sum & 0xffff) + (sum >> 16);
    return htons(0xffff - sum);
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
    iph->id = htons(35897);
    iph->frag_off = htons(12345);
    iph->ttl = span->ttl;
    iph->protocol = IPPROTO_ICMP;
    iph->check = 0;
    iph->saddr = (uint32_t) span->src->s_addr;
    iph->daddr = (uint32_t) span->dest->s_addr;

    // create ICMP header
    icmphd->type = ICMP_ECHO;
    icmphd->code = 0;
    icmphd->checksum = 0;
    icmphd->checksum = calc_checksum((unsigned short *) (packet + sizeof(struct iphdr)), 4);

    // calculate IP checksum
    iph->check = calc_checksum((unsigned short *) packet, iph->tot_len >> 1);

    // create UDP header
    struct udphdr *udp = (struct udphdr *) (packet + sizeof(struct iphdr) + sizeof(struct icmphdr));
    udp->source = htons(50000);
    udp->dest = (63000);
    udp->len = htons(8);
    udp->check = 0;
    udp->check = calc_checksum((unsigned short *) (packet + sizeof(struct iphdr) + sizeof(struct icmphdr)), 4);

    return packet;
}

int main(int argc, char **argv) {
    // argument check
    if (argc < 2) {
        fprintf(stderr, "Illegal use of traceroute: ./traceroute [DESTINATION_DOMAIN] [NETWORKING_INTERFACE=eth0].\n");
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
        fprintf(stderr, "Cannot find networking interface!\n");
        return 1;
    }

    // check and resolve destination hostname
    char *hostname = argv[1];
    struct in_addr dest;

    if (0 != hostname_to_ip(hostname, &dest)) {
        fprintf(stderr, "Unable to resolve destination host '%s'!\n", hostname);
        return 1;
    }

    char ip[15];
    strcpy(ip, inet_ntoa(dest));

    printf("tracing down '%s' on '%s'..\n", hostname, ip);

    // finally bind raw socket
    int on = 1;
    int out_sock = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
    if (0 > out_sock) {
        fprintf(stderr, "Error creating raw socket!\n");
        return -1;
    }
    if (0 != setsockopt(out_sock, IPPROTO_IP, IP_HDRINCL, (const char *) &on, sizeof(on))) {
        fprintf(stderr, "Error setting socket options!\n");
        return -1;
    }

    // build next raceroute span
    struct trace_span span;
    span.ttl = 1;
    span.src = &src;
    span.dest = &dest;

    char *packet = build_span(&span);

    struct sockaddr_in dest_sockaddr;
    dest_sockaddr.sin_family = AF_INET;
    dest_sockaddr.sin_addr.s_addr = dest.s_addr;
    dest_sockaddr.sin_port = htons(80);

    // send span
    printf("Sending span %d..\n", span.ttl);
    ssize_t dat = sendto(out_sock, packet, sizeof(struct iphdr) + sizeof(struct icmphdr) + sizeof(struct udphdr), 0,
                         (struct sockaddr *) &dest_sockaddr, sizeof dest_sockaddr);
    printf("Sent! %d\n", (int) dat);

    free(packet);

    // receive packet
//    int in_sock = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
//    setsockopt(in_sock, IPPROTO_IP, IP_HDRINCL, (const char *) &on, sizeof(on));
//    char buf[65536];
//    ssizet_t ret = read(icmpsock, buf, sizeof(buf));

    return 0;
}
