#include <net/ethernet.h>
#include <net/arp.h>
#include <lib/print.h>

void process_frame(struct nic *nic, struct eth_frame *frame, size_t len) {
    print("\npreocessing frame %x\n", frame->ethertype);
    switch (NTOHS(frame->ethertype)) {
        case ETH_P_ARP : {
            print("GOT AN ARP PACKET\n");

            handle_arp(nic, (struct arp_frame*)frame->payload, len);
        }
    }
}

//payload is assumed to have enough space at the beginning for a ethernet header
//and at the end for the fcs
void eth_encapsulate(struct nic *nic, void* payload,
        size_t len, unsigned char dmac[6],
        unsigned char smac[6], uint16_t ethertype) {
    struct eth_frame *p = payload;
    memcpy(p->dmac, dmac, MAC_ADDR_SIZE);
    memcpy(p->smac, smac, MAC_ADDR_SIZE);
    p->ethertype = HTONS(ethertype);
}
