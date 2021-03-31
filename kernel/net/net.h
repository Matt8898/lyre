#ifndef NET_H
#define NET_H

#define HTONS(n) ((uint16_t)(((((uint16_t)(n) & 0xFFu)) << 8u) | (((uint16_t)(n) & 0xFF00u) >> 8u)))
#define NTOHS(n) ((uint16_t)(((((uint16_t)(n) & 0xFFu)) << 8u) | (((uint16_t)(n) & 0xFF00u) >> 8u)))

#define HTONL(n) (((((unsigned long)(n) & 0xFFu)) << 24u) | \
                  ((((unsigned long)(n) & 0xFF00u)) << 8u) | \
                  ((((unsigned long)(n) & 0xFF0000u)) >> 8u) | \
                  ((((unsigned long)(n) & 0xFF000000u)) >> 24u))

#define NTOHL(n) (((((unsigned long)(n) & 0xFFu)) << 24u) | \
                  ((((unsigned long)(n) & 0xFF00u)) << 8u) | \
                  ((((unsigned long)(n) & 0xFF0000u)) >> 8u) | \
                  ((((unsigned long)(n) & 0xFF000000u)) >> 24u))


#define PKT_FLAG_IP_CS   (1u << 0u)
#define PKT_FLAG_UDP_CS  (1u << 1u)
#define PKT_FLAG_TCP_CS  (1u << 2u)

#include <stdint.h>
#include <stddef.h>

struct nic {
    unsigned char mac[6];
    int (*send_packet) (struct nic*, void *pkt, size_t len, uint64_t flags);
};

void register_nic(struct nic* nic);

#endif
