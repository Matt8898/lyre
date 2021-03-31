#include <dev/dev.h>
#include <sys/pci.h>
#include <lib/alloc.h>
#include <lib/print.h>
#include <lib/errno.h>
#include <mm/vmm.h>
#include <sys/idt.h>
#include <net/net.h>
#include <stdint.h>
#include <net/net.h>
#include <net/ethernet.h>
#include <net/arp.h>

#define RTL_VENDOR_ID 0x10ec
#define RX_BUFFER_SIZE  (1536u)
#define RX_RING_SIZE    (64u)
#define TX_RING_SIZE    (64u)

/* Mac Address */
#define IDR0            (0x0000)
#define IDR1            (0x0001)
#define IDR2            (0x0002)
#define IDR3            (0x0003)
#define IDR4            (0x0004)
#define IDR5            (0x0005)

/* Multicase Address */
#define MAR0            (0x0008)
#define MAR1            (0x0007)
#define MAR2            (0x000a)
#define MAR3            (0x000b)
#define MAR4            (0x000c)
#define MAR5            (0x000d)
#define MAR6            (0x000e)
#define MAR7            (0x000f)

/* TX ring */
#define TNPDS_LOW       (0x0020)
#define TNPDS_HIGH      (0x0024)

/* TX high priority ring */
#define THPDS_LOW       (0x0028)
#define HNPDS_HIGH      (0x003b)

/* Command Registe */
#define CR              (0x0037)
#define     RST             (1u << 4u) /* Reset */
#define     RE              (1u << 3u) /* Receiver enable */
#define     TE              (1u << 2u) /* Transmit enable */

/* Transmit polling */
#define TPPoll          (0x0038)
#define TPPoll_8139     (0x00d9) /* The rtl8139 has a different register */
#define     HQP             (1u << 7u) /* Trigger high priority queue */
#define     NPQ             (1u << 6u) /* Trigger normal priority queue */

/* Interrupt Mask and Status registers */
#define IMR             (0x003C)
#define ISR             (0x003E)
#define     ROK             (1u << 0u) /* Rx Ok Interrupt */
#define     RER             (1u << 1u) /* Rx Error Interrupt */
#define     TOK             (1u << 2u) /* Tx Ok Interrupt */
#define     TER             (1u << 3u) /* Tx Error Interrupt */
#define     RDU             (1u << 4u) /* Rx Buffer Overflow */
#define     PUN             (1u << 5u) /* Packet Underrun */
#define     FOVW            (1u << 6u) /* Rx Fifo Overflow */
#define     TDU             (1u << 7u) /* Tx Descriptor Unavailable */
#define     SWInt           (1u << 8u) /* Software Interrupt */
#define     LenChg_8139     (1u << 13u) /* Cable Length Change */
#define     TimeOut         (1u << 14u) /* Time out */
#define     SERR            (1u << 15u) /* System Error */

/* TX and RX configuration registers */
#define TCR             (0x0040)
#define     IFG_NORMAL      (0b11u << 24u) /* InterFrameGap Time */
#define     CRC             (1u << 16u) /* Append CRC */

#define RCR             (0x0044)
#define     RXFTH_NONE      (0b111u << 13u) /* no rx threshold */
#define     MXDMA_UNLIMITED (0b111u << 8u) /* no mac size of dma data burst */
#define     AB              (1u << 3u) /* Accept Broadcast Packets */
#define     APM             (1u << 1u) /* Accept Physical Match Packets */

/* Configuration registers */
#define CR9346          (0x0050)
#define     CR9346_Unlock   (0b11u << 6u) /* Unlock config registers */
#define     CR9346_Lock     (0u) /* Lock config registers */
#define CONFIG0         (0x0051)
#define CONFIG1         (0x0052)
#define CONFIG2         (0x0053)
#define CONFIG3         (0x0054)
#define CONFIG4         (0x0055)
#define CONFIG5         (0x0056)

/* RX packet max size */
#define RMS             (0x00DA)
#define RMS_MASK        (0xe)

#define CPCR            (0x00E0)
/* rtl81x9 */
#define     RxChkSum        (1u << 5u) /*  */
/* rtl8139 */
#define     CPRx            (1u << 1u) /* Receive enable */
#define     CPTx            (1u << 0u) /* Transmit enable */

/* RX ring */
#define RDSAR_LOW       (0x00E4)
#define RDSAR_HIGH      (0x00E8)

#define MTPS            (0x00EC)

struct __attribute((packed)) pkt_desc {
    uint32_t opts1;
#define FRAME_LENGTH_MASK 0xfff
#define OWN     (1u << 31u)
#define EOR     (1u << 30u)
#define FS      (1u << 29u)
#define LS      (1u << 28u)
    // RX ONLY
    // for rtl8139
    #define IPF_RTL8139     (1u << 15u)
    #define UDPF_RTL8139    (1u << 14u)
    #define TCPF_RTL8139    (1u << 13u)
    #define IPF             (1u << 16u)
    #define UDPF            (1u << 15u)
    #define TCPF            (1u << 14u)

    // TX ONLY
    #define IPCS    (1u << 18u)
    #define UDPCS   (1u << 17u)
    #define TCPCS   (1u << 16u)

    uint32_t opts2;
    uint64_t buff;
};

// as defined by the spec
#define RX_MAX_ENTRIES 1024
#define TX_MAX_ENTRIES 1024


struct rtl_device {
    uint32_t *bar0;
};

struct r81x9_device {
    struct nic;
    // device info
    uintptr_t base;
    int irq_line;
    int poll_reg;
    unsigned ipf;
    unsigned udpf;
    unsigned tcpf;

    // rings
    volatile struct pkt_desc* rx_ring;
    volatile struct pkt_desc* tx_ring;

    // index in ring
    size_t rxi;

    size_t txi;
    size_t prev_txi;
};

static void process_sent_packets(struct r81x9_device* dev) {

    // iterate over the sent packets
    for (; dev->prev_txi != dev->txi; dev->prev_txi = (dev->prev_txi + 1) % TX_RING_SIZE) {
        volatile struct pkt_desc* desc = &dev->tx_ring[dev->prev_txi];

        // only touch it if it was sent, we can assume
        // the following ones were not sent as well
        if (desc->opts1 & OWN) {
            break;
        }

        // simply free the buffer
        free((void *) (desc->buff + MEM_PHYS_OFFSET));

        desc->opts1 &= EOR;
        desc->opts2 = 0;
        desc->buff = 0;
    }
}

/**
 * This is called on ROK interrupt. It will go through the
 */
static void process_received_packets(struct r81x9_device* dev) {
    for (size_t left = RX_RING_SIZE; left > 0; left--, dev->rxi = (dev->rxi + 1) % RX_RING_SIZE) {
        print("\ngotpacket\n");
        volatile struct pkt_desc* desc = &dev->rx_ring[dev->rxi];

        // make sure the nic does not own the desc
        if (desc->opts1 & OWN) {
            break;
        }

        // make sure we do not touch descriptor
        // which is not ours

        // TODO: support packet split
        if (!(desc->opts1 & (LS | FS))) {
            print("rtl81x9: split packets are not supported currently");
            continue;
        }

        // copy the buffer and packet
        uint16_t len = (desc->opts1 & FRAME_LENGTH_MASK) - 4; // ignore the fcs
        uintptr_t buf = desc->buff + MEM_PHYS_OFFSET;

        // get packet flags
        uint64_t flags = 0;

        if (!(desc->opts1 & dev->ipf)) {
            flags |= PKT_FLAG_IP_CS;
        }
        if (!(desc->opts1 & dev->udpf)) {
            flags |= PKT_FLAG_UDP_CS;
        }
        if (!(desc->opts1 & dev->tcpf)) {
            flags |= PKT_FLAG_TCP_CS;
        }

/*        struct packet pkt = {
            .buf = (char *)buf,
            .pkt_len = len,
        };*/

        // let the network stack handle it
        process_frame(dev, (struct eth_frame*)buf, len);

        // reset the descriptor
        uint16_t eor = desc->opts1 * EOR;
        desc->opts2 = 0;
        desc->opts1 = (eor | OWN | RX_BUFFER_SIZE);
    }
}

static void irq_handler(struct r81x9_device* dev) {
    for (;;) {
        // wait for an interrupt and get the event
        ssize_t which = 0;
        events_await((struct event *[]){int_event[dev->irq_line]}, &which, 1, false);
        volatile uint16_t* isr_reg = (uint32_t*)(dev->base + ISR);
        uint16_t isr = *isr_reg;

        // got a packet
        if (isr & ROK) {
            process_received_packets(dev);
        }

        // sent packets
        if (isr & TOK) {
            process_sent_packets(dev);
        }

        // will help us with catching errors
        /*
        if (isr & RER) kprint(KPRN_ERR, "rtl81x9: Rx Error");
        if (isr & TER) kprint(KPRN_ERR, "rtl81x9: Tx Error");
        if (isr & RDU) kprint(KPRN_ERR, "rtl81x9: Rx Descriptor Unavailable");
        if (isr & TDU) kprint(KPRN_ERR, "rtl81x9: Tx Descriptor Unavailable");
        if (isr & SERR) kprint(KPRN_ERR, "rtl81x9: System error");
        */

        // clear status bits
        *isr_reg = isr;
    }

}

//TODO these are generic network things
struct mac_addr {
    uint8_t raw[6];
} __attribute__((packed));

static int send_packet(struct nic *nic, void *pkt, size_t len, uint64_t flags) {
    // get the card
    struct r81x9_device* dev = (struct r81x9_device*)nic;

    print("packet dump:\n");
    uint8_t* p = pkt;
    for (int i = 0; i < len; i ++) {
        print("%X ", *p++);
    }
    print("packet dump end:\n");

    // check if we have a free descriptor
    volatile struct pkt_desc* desc = &dev->tx_ring[dev->txi];
    volatile uint8_t* poll = (uint32_t*)(dev->base + dev->poll_reg);
    if (desc->opts1 & OWN) {
        // no space for more packets try and trigger the
        // nic to send some packets
        *poll = NPQ;

        // try again later
        errno = EAGAIN;
        return -1;
    }

    // modify the descriptor
    desc->opts1 |= (len | OWN | LS | FS);
    desc->opts2 = 0;
    desc->buff = (uintptr_t)pkt - MEM_PHYS_OFFSET;

    // set flags
    if (flags & PKT_FLAG_IP_CS) {
        desc->opts1 |= IPCS;
    }
    if (flags & PKT_FLAG_UDP_CS) {
        desc->opts1 |= UDPCS;
    }
    if (flags & PKT_FLAG_TCP_CS) {
        desc->opts1 |= TCPCS;
    }

    // increment to the next packet
    dev->txi++;

    // tell the nic to send it
    *poll = NPQ;
    return 0;
}

static bool rtl8169_init(struct pci_device *dev) {
    struct r81x9_device *rdev = alloc(sizeof(struct r81x9_device));

    struct pci_bar_t bar = {0};
    //TODO do proper bar finding
    pci_read_bar(dev, 1, &bar);

//    volatile uint32_t *bar0_base = (uint32_t*)(bar.base + MEM_PHYS_OFFSET);
//    rtl8169_dev->bar0 = bar0_base;
    pci_enable_busmastering(dev);
    pci_enable_interrupts(dev);

    rdev->base = MEM_PHYS_OFFSET + (uintptr_t)bar.base;
    print("base: %X\n", rdev->base);

    volatile uint8_t* cr = (uint32_t*)(rdev->base + CR);
    volatile uint32_t* rcr = (uint32_t*)(rdev->base + RCR);
    volatile uint32_t* tcr = (uint32_t*)(rdev->base + TCR);
    volatile uint16_t* cpcr = (uint32_t*)(rdev->base + CPCR);
    volatile uint32_t* rdsar_low = (uint32_t*)(rdev->base + RDSAR_LOW);
    volatile uint32_t* rdsar_high = (uint32_t*)(rdev->base + RDSAR_HIGH);
    volatile uint32_t* tnpds_low = (uint32_t*)(rdev->base + TNPDS_LOW);
    volatile uint32_t* tnpds_high = (uint32_t*)(rdev->base + TNPDS_HIGH);
    volatile uint16_t* imr = (uint32_t*)(rdev->base + IMR);
    volatile uint16_t* isr = (uint32_t*)(rdev->base + ISR);

    *cr = RST;

    print("rtl: resetting card\n");
    while (*cr & RST) {}

    print("rtl: card reset\n");

    rdev->rx_ring = alloc(sizeof(struct pkt_desc) * RX_RING_SIZE);
    rdev->tx_ring = alloc(sizeof(struct pkt_desc) * TX_RING_SIZE);

    // allocate a bunch of tx buffers
    uintptr_t pkt_buffs_base = (uintptr_t) pmm_alloc((RX_RING_SIZE * RX_BUFFER_SIZE) / PAGE_SIZE);

    // setup the rx descriptors
    for (size_t i = 0; i < RX_RING_SIZE; i++, pkt_buffs_base += RX_BUFFER_SIZE) {
        // setup the rx entry
        volatile struct pkt_desc* desc = &rdev->rx_ring[i];
        desc->opts1 = (OWN | RX_BUFFER_SIZE);
        desc->opts2 = 0;
        desc->buff = pkt_buffs_base;
    }

    // set the end of ring bit for the tx & rx
    rdev->rx_ring[RX_RING_SIZE - 1].opts1 |= EOR;
    rdev->tx_ring[TX_RING_SIZE - 1].opts1 |= EOR;

    /*
     * Accept broadcast and physically match packets
     * Unlimited DMA burst
     * No rx threshold
     */
    *rcr = APM | AB | MXDMA_UNLIMITED | RXFTH_NONE;

    /**
     * append crc to every frame
     * Unlimited DMA burst
     * normal IFG
     */
    *cr = TE;
    *tcr = MXDMA_UNLIMITED | CRC | IFG_NORMAL;

    // setup rx checksum checking
    // on 8139 we need to enable C+ mode on the RX and TX rings
    // also on the 8139 the poll register is at a different offset
    if (dev->device_id == 0x8139) {
        rdev->poll_reg = TPPoll_8139;
        rdev->ipf = IPF_RTL8139;
        rdev->udpf = UDPF_RTL8139;
        rdev->tcpf = TCPF_RTL8139;
        print("\nENABLING CPCR\n");
        *cpcr = RxChkSum | CPRx | CPTx;
    } else {
        rdev->poll_reg = TPPoll;
        rdev->ipf = IPF;
        rdev->udpf = UDPF;
        rdev->tcpf = TCPF;
        *cpcr = RxChkSum;
    }

    // setup the descriptors
    uintptr_t rx_ring_phys = (uintptr_t)rdev->rx_ring - MEM_PHYS_OFFSET;
    uintptr_t tx_ring_phys = (uintptr_t)rdev->tx_ring - MEM_PHYS_OFFSET;
    *rdsar_low  = rx_ring_phys & 0xFFFFFFFF;
    *rdsar_high = (rx_ring_phys >> 32u) & 0xFFFFFFFF;
    *tnpds_low  = tx_ring_phys & 0xFFFFFFFF;
    *tnpds_high = (tx_ring_phys >> 32u) & 0xFFFFFFFF;


//    dev->rdev->flags = NIC_RX_IP_CS | NIC_RX_UDP_CS |NIC_RX_TCP_CS | NIC_TX_IP_CS | NIC_TX_UDP_CS | NIC_TX_TCP_CS;
/*    rdev->mac[0] = mmio_read8(dev->base + IDR0);
    rdev->mac[1] = mmio_read8(dev->base + IDR1);
    rdev->mac[2] = mmio_read8(dev->base + IDR2);
    rdev->mac[3] = mmio_read8(dev->base + IDR3);
    rdev->mac[4] = mmio_read8(dev->base + IDR4);
    rdev->mac[5] = mmio_read8(dev->base + IDR5);*/
    memcpy(rdev->mac, rdev->base, MAC_ADDR_SIZE);

    // set interrupt handler
    rdev->irq_line = idt_get_empty_int_vector();
    if (!pci_register_msi(dev, rdev->irq_line)) {
        print("rtl: failed to init msi, pin-based interrupts are not supported\n");
    }

    // enable Rx and Tx rings
    *cr = RE | TE;

    // enable interrupts
    *imr = ROK | TOK | TER | RER | SERR | RDU | TDU;
    *isr = isr;

    print("rtl: init complete");

    sched_new_thread(NULL, kernel_process, false, irq_handler, rdev, NULL, NULL, NULL, true, NULL);

    void* buf = alloc(64);

    rdev->send_packet = send_packet;
    register_nic(rdev);

    unsigned char result[6] = {0};
    arp_request(rdev, 0x0100a8c0, &result);

    print("\nsent packet\n");

    while (1) {}
}

PCI_VENDOR_DRIVER(
        rtl8169_init, {0x10ec, 0x8168}, {0x10ec, 0x8139}, {0x10ec, 0x8169});
