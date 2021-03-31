#ifndef ETHER_H
#define ETHER_H

#define ETH_P_IP	0x0800		/* Internet Protocol packet	*/
#define ETH_P_ARP	0x0806		/* Address Resolution packet	*/
#include <stdint.h>
#include <net/net.h>

#define MAC_ADDR_SIZE 6
#define ETH_SIZE offsetof(struct eth_frame, payload)

struct eth_frame {
    unsigned char dmac[6];
    unsigned char smac[6];
    uint16_t ethertype;
    unsigned char payload[];
} __attribute__((packed));

#define ETHERNET_HDR_SIZE offsetof(eth_frame, payload)

void process_frame(struct nic *nic, struct eth_frame *frame, size_t len);
void eth_encapsulate(struct nic *nic, void* payload,
        size_t len, unsigned char dmac[6],
        unsigned char smac[6], uint16_t ethertype);

#endif
