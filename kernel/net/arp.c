#include <net/net.h>
#include <net/arp.h>
#include <net/ethernet.h>
#include <lib/print.h>
#include <lib/alloc.h>
#include <lib/builtins.h>
#include <stdbool.h>
#include <lib/event.h>

#define ARP_TABLE_SIZE 32

#define ARP_ETHERNET    0x0001
#define ARP_IPV4        0x0800
#define ARP_REQUEST     0x0001
#define ARP_REPLY       0x0002

struct arp_ipv4 {
    unsigned char smac[6];
    uint32_t sip;
    unsigned char dmac[6];
    uint32_t dip;
} __attribute__((packed));

struct arp_table_entry {
    uint16_t hwtype;
    uint32_t ip;
    unsigned char mac[6];
    bool empty;
};

//TODO add locking
struct arp_event {
    struct event event;
    uint32_t requested_ip;
    struct arp_event* next;
};

struct arp_event* arp_event_list = NULL;

static struct arp_table_entry arp_table[ARP_TABLE_SIZE] = {0};
int last_replaced = 0;

void arp_request(struct nic* nic, uint32_t ip, unsigned char* mac) {
        size_t l = sizeof(struct eth_frame) + sizeof(struct arp_frame) + sizeof(struct arp_ipv4) + 4;
        void *newpacket = alloc(l);

        print("nepacket %x\n", ETH_SIZE);

        struct arp_frame *arphdr  = (struct arp_frame*)((uintptr_t)newpacket + ETH_SIZE);
        struct arp_ipv4  *arpdata = (struct arp_ipv4*)((uintptr_t)newpacket + ETH_SIZE + offsetof(struct arp_frame, data));
        struct arp_event event = {.event = event_create(1), .requested_ip = ip};

        unsigned char broadcast_mac[6] = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff};
        memcpy(arpdata->dmac, broadcast_mac, MAC_ADDR_SIZE);
//        arpdata->dip = arpip->sip;
        //TODO make these actually real
        unsigned char ourmac[6] = {0x43, 0x23, 0x45, 0x34, 0x45, 0xff};
        memcpy(arpdata->smac, nic->mac, MAC_ADDR_SIZE);
        arpdata->sip = 0xc0a80002;
        arpdata->dip = ip;

        arphdr->opcode = HTONS(ARP_REQUEST);
        arphdr->hwtype = HTONS(ARP_ETHERNET);
        arphdr->protype = HTONS(ARP_IPV4);
        arphdr->hwsize = (0x6);
        arphdr->prosize = (0x4);
        eth_encapsulate(nic, newpacket, l, broadcast_mac, ourmac, ETH_P_ARP);

        print("\nsending arp request\n");
        nic->send_packet(nic, newpacket, l, 0);

        if (arp_event_list == NULL) {
            arp_event_list = &event;
        } else {
            struct arp_event* cur = arp_event_list;
            while (cur->next != NULL) {
                cur = cur->next;
            }
            cur->next = &event;
        }

        size_t which;
        events_await((struct event *[]){&event}, &which, 1, false);
        while (1) {}
}

static void insert_translation(struct arp_frame *frame, struct arp_ipv4 *data) {
    for(int i = 0; i < ARP_TABLE_SIZE; i++) {
        if (arp_table[i].empty) {
            arp_table[i].empty = false;
            arp_table[i].hwtype = frame->hwtype;
            arp_table[i].ip = data->sip;
            memcpy(arp_table[i].mac, data->smac, MAC_ADDR_SIZE);
            return;
        }
    }

    arp_table[last_replaced].empty = false;
    arp_table[last_replaced].hwtype = frame->hwtype;
    arp_table[last_replaced].ip = data->sip;
    memcpy(arp_table[last_replaced].mac, data->smac, MAC_ADDR_SIZE);
    last_replaced = (last_replaced + 1) % ARP_TABLE_SIZE;

    struct arp_event* cur = arp_event_list;
    struct arp_event* prev = NULL;
    while (cur != NULL) {
        if (cur->requested_ip == data->sip) {
            print("triggering event for ip");
            event_trigger(&cur->event);

            if (cur->next == NULL) {
                arp_event_list = NULL;
            } else {
                prev->next = cur->next;
            }
            return;
        }
        cur = cur->next;
        prev = cur;
    }
}

static bool update_entry(struct arp_frame *frame, struct arp_ipv4 *data) {
    for(int i = 0; i < ARP_TABLE_SIZE; i++) {
        if (!arp_table[i].empty && (arp_table[i].hwtype == frame->hwtype) && (arp_table[i].ip = data->sip)) {
            memcpy(arp_table[i].mac, data->smac, MAC_ADDR_SIZE);
            return true;
        }
    }
    return false;
}


void handle_arp(struct nic *nic, struct arp_frame *frame, size_t len) {
    return;
    frame->hwtype = NTOHS(frame->hwtype);
    frame->protype = NTOHS(frame->protype);
    frame->opcode = NTOHS(frame->opcode);

    if (frame->hwtype != ARP_ETHERNET) {
        print("unsupported hwtype in arp packet\n");
        return;
    }

    if (frame->protype != ARP_IPV4) {
        print("unsupported arp protocol\n");
        return;
    }

    struct arp_ipv4 *arpip = (struct arp_ipv4*)frame->data;

    bool merge = update_entry(frame, arpip);

    // not for us, TODO actually check this (if we are the destination)
    if (false) {
        return;
    }

    if (!merge) {
        insert_translation(frame, arpip);
    }

    if (frame->opcode == ARP_REQUEST) {
        print("ARP REQUEST\n");
        size_t l = sizeof(struct eth_frame) + sizeof(struct arp_frame) + sizeof(struct arp_ipv4) + 4;
        void *newpacket = alloc(l);

        print("nepacket %x\n", ETH_SIZE);

        struct arp_frame *arphdr  = (struct arp_frame*)((uintptr_t)newpacket + ETH_SIZE);
        struct arp_ipv4  *arpdata = (struct arp_ipv4*)((uintptr_t)newpacket + ETH_SIZE + offsetof(struct arp_frame, data));
        
        memcpy(arpdata->dmac, arpip->smac, MAC_ADDR_SIZE);
        arpdata->dip = arpip->sip;
        //TODO make these actually real
        unsigned char ourmac[6] = {0x43, 0x23, 0x45, 0x34, 0x45, 0xff};
        memcpy(arpdata->smac, nic->mac, MAC_ADDR_SIZE);
        arpdata->sip = arpip->dip;

        arphdr->opcode = HTONS(ARP_REPLY);
        arphdr->hwtype = HTONS(frame->hwtype);
        arphdr->protype = HTONS(frame->protype);
        arphdr->hwsize = (frame->hwsize);
        arphdr->prosize = (frame->prosize);
        eth_encapsulate(nic, newpacket, l, arpdata->dmac, nic->mac, ETH_P_ARP);

        nic->send_packet(nic, newpacket, l, 0);
    }
}
