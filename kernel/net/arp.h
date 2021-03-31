#ifndef ARP_H
#define ARP_H

struct arp_frame {
    uint16_t hwtype;
    uint16_t protype;
    unsigned char hwsize;
    unsigned char prosize;
    uint16_t opcode;
    unsigned char data[];
} __attribute__((packed));


void handle_arp(struct nic *nic, struct arp_frame *frame, size_t len);

#endif
