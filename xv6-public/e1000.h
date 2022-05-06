#ifndef JOS_KERN_E1000_H
#define JOS_KERN_E1000_H


#define PCI_VENDOR_82540EM   0x8086
#define PCI_PRODUCT_82540EM  0x100E

#define E1000_STATUS         0x00008   /* Device Status  - R   */

#define E1000_TDBAL          0x03800   /* Transmit Descriptor Base Low  - R/W */
#define E1000_TDBAH          0x03804   /* Transmit Descriptor Base High - R/W */
#define E1000_TDLEN          0x03808   /* Transmit Descriptor Length    - R/W */
#define E1000_TDH            0x03810   /* Transmit Descriptor Head      - R/W */
#define E1000_TDT            0x03818   /* Transmit Descriptor Tail      - R/W */

#define E1000_ICR      0x000C0  /* Interrupt Cause Read - R/clr */
#define E1000_ITR      0x000C4  /* Interrupt Throttling Rate - RW */
#define E1000_ICS      0x000C8  /* Interrupt Cause Set - WO */
#define E1000_IMS      0x000D0  /* Interrupt Mask Set - RW */
#define E1000_EIAC     0x000DC  /* Ext. Interrupt Auto Clear - RW */
#define E1000_IMC      0x000D8  /* Interrupt Mask Clear - WO */
#define E1000_IAM      0x000E0  /* Interrupt Acknowledge Auto Mask */
#define E1000_IVAR     0x000E4  /* Interrupt Vector Allocation Register - RW */
#define E1000_EITR 0x000E8 /* Extended Interrupt Throttling Rate - RW */



/* Interrupt Cause Read */
#define E1000_ICR_TXDW          0x00000001 /* Transmit desc written back */
#define E1000_ICR_TXQE          0x00000002 /* Transmit Queue empty */
#define E1000_ICR_LSC           0x00000004 /* Link Status Change */
#define E1000_ICR_RXSEQ         0x00000008 /* rx sequence error */
#define E1000_ICR_RXDMT0        0x00000010 /* rx desc min. threshold (0) */
#define E1000_ICR_RXO           0x00000040 /* rx overrun */
#define E1000_ICR_RXT0          0x00000080 /* rx timer intr (ring 0) */
#define E1000_ICR_MDAC          0x00000200 /* MDIO access complete */
#define E1000_ICR_RXCFG         0x00000400 /* RX /c/ ordered set */
#define E1000_ICR_GPI_EN0       0x00000800 /* GP Int 0 */
#define E1000_ICR_GPI_EN1       0x00001000 /* GP Int 1 */
#define E1000_ICR_GPI_EN2       0x00002000 /* GP Int 2 */
#define E1000_ICR_GPI_EN3       0x00004000 /* GP Int 3 */
#define E1000_ICR_TXD_LOW       0x00008000
#define E1000_ICR_SRPD          0x00010000
#define E1000_ICR_ACK           0x00020000 /* Receive Ack frame */
#define E1000_ICR_MNG           0x00040000 /* Manageability event */
#define E1000_ICR_DOCK          0x00080000 /* Dock/Undock */
#define E1000_ICR_INT_ASSERTED  0x80000000 /* If this bit asserted, the driver should claim the interrupt */
#define E1000_ICR_RXD_FIFO_PAR0 0x00100000 /* queue 0 Rx descriptor FIFO parity error */
#define E1000_ICR_TXD_FIFO_PAR0 0x00200000 /* queue 0 Tx descriptor FIFO parity error */
#define E1000_ICR_HOST_ARB_PAR  0x00400000 /* host arb read buffer parity error */
#define E1000_ICR_PB_PAR        0x00800000 /* packet buffer parity error */
#define E1000_ICR_RXD_FIFO_PAR1 0x01000000 /* queue 1 Rx descriptor FIFO parity error */
#define E1000_ICR_TXD_FIFO_PAR1 0x02000000 /* queue 1 Tx descriptor FIFO parity error */
#define E1000_ICR_ALL_PARITY    0x03F00000 /* all parity error bits */
#define E1000_ICR_DSW           0x00000020 /* FW changed the status of DISSW bit in the FWSM */
#define E1000_ICR_PHYINT        0x00001000 /* LAN connected device generates an interrupt */
#define E1000_ICR_EPRST         0x00100000 /* ME handware reset occurs */
#define E1000_ICR_RXQ0          0x00100000 /* Rx Queue 0 Interrupt */
#define E1000_ICR_RXQ1          0x00200000 /* Rx Queue 1 Interrupt */
#define E1000_ICR_TXQ0          0x00400000 /* Tx Queue 0 Interrupt */
#define E1000_ICR_TXQ1          0x00800000 /* Tx Queue 1 Interrupt */
#define E1000_ICR_OTHER         0x01000000 /* Other Interrupts */

#define E1000_ICR_OTHER_CAUSES (E1000_ICR_LSC  | \
                                E1000_ICR_RXO  | \
                                E1000_ICR_MDAC | \
                                E1000_ICR_SRPD | \
                                E1000_ICR_ACK  | \
                                E1000_ICR_MNG)

/* Interrupt Cause Set */
#define E1000_ICS_TXDW      E1000_ICR_TXDW      /* Transmit desc written back */
#define E1000_ICS_TXQE      E1000_ICR_TXQE      /* Transmit Queue empty */
#define E1000_ICS_LSC       E1000_ICR_LSC       /* Link Status Change */
#define E1000_ICS_RXSEQ     E1000_ICR_RXSEQ     /* rx sequence error */
#define E1000_ICS_RXDMT0    E1000_ICR_RXDMT0    /* rx desc min. threshold */
#define E1000_ICS_RXO       E1000_ICR_RXO       /* rx overrun */
#define E1000_ICS_RXT0      E1000_ICR_RXT0      /* rx timer intr */
#define E1000_ICS_MDAC      E1000_ICR_MDAC      /* MDIO access complete */
#define E1000_ICS_RXCFG     E1000_ICR_RXCFG     /* RX /c/ ordered set */
#define E1000_ICS_GPI_EN0   E1000_ICR_GPI_EN0   /* GP Int 0 */
#define E1000_ICS_GPI_EN1   E1000_ICR_GPI_EN1   /* GP Int 1 */
#define E1000_ICS_GPI_EN2   E1000_ICR_GPI_EN2   /* GP Int 2 */
#define E1000_ICS_GPI_EN3   E1000_ICR_GPI_EN3   /* GP Int 3 */
#define E1000_ICS_TXD_LOW   E1000_ICR_TXD_LOW
#define E1000_ICS_SRPD      E1000_ICR_SRPD
#define E1000_ICS_ACK       E1000_ICR_ACK       /* Receive Ack frame */
#define E1000_ICS_MNG       E1000_ICR_MNG       /* Manageability event */
#define E1000_ICS_DOCK      E1000_ICR_DOCK      /* Dock/Undock */
#define E1000_ICS_RXD_FIFO_PAR0 E1000_ICR_RXD_FIFO_PAR0 /* queue 0 Rx descriptor FIFO parity error */
#define E1000_ICS_TXD_FIFO_PAR0 E1000_ICR_TXD_FIFO_PAR0 /* queue 0 Tx descriptor FIFO parity error */
#define E1000_ICS_HOST_ARB_PAR  E1000_ICR_HOST_ARB_PAR  /* host arb read buffer parity error */
#define E1000_ICS_PB_PAR        E1000_ICR_PB_PAR        /* packet buffer parity error */
#define E1000_ICS_RXD_FIFO_PAR1 E1000_ICR_RXD_FIFO_PAR1 /* queue 1 Rx descriptor FIFO parity error */
#define E1000_ICS_TXD_FIFO_PAR1 E1000_ICR_TXD_FIFO_PAR1 /* queue 1 Tx descriptor FIFO parity error */
#define E1000_ICS_DSW       E1000_ICR_DSW
#define E1000_ICS_PHYINT    E1000_ICR_PHYINT
#define E1000_ICS_EPRST     E1000_ICR_EPRST

/* Interrupt Mask Set */
#define E1000_IMS_TXDW      E1000_ICR_TXDW      /* Transmit desc written back */
#define E1000_IMS_TXQE      E1000_ICR_TXQE      /* Transmit Queue empty */
#define E1000_IMS_LSC       E1000_ICR_LSC       /* Link Status Change */
#define E1000_IMS_RXSEQ     E1000_ICR_RXSEQ     /* rx sequence error */
#define E1000_IMS_RXDMT0    E1000_ICR_RXDMT0    /* rx desc min. threshold */
#define E1000_IMS_RXO       E1000_ICR_RXO       /* rx overrun */
#define E1000_IMS_RXT0      E1000_ICR_RXT0      /* rx timer intr */
#define E1000_IMS_MDAC      E1000_ICR_MDAC      /* MDIO access complete */
#define E1000_IMS_RXCFG     E1000_ICR_RXCFG     /* RX /c/ ordered set */
#define E1000_IMS_GPI_EN0   E1000_ICR_GPI_EN0   /* GP Int 0 */
#define E1000_IMS_GPI_EN1   E1000_ICR_GPI_EN1   /* GP Int 1 */
#define E1000_IMS_GPI_EN2   E1000_ICR_GPI_EN2   /* GP Int 2 */
#define E1000_IMS_GPI_EN3   E1000_ICR_GPI_EN3   /* GP Int 3 */
#define E1000_IMS_TXD_LOW   E1000_ICR_TXD_LOW
#define E1000_IMS_SRPD      E1000_ICR_SRPD
#define E1000_IMS_ACK       E1000_ICR_ACK       /* Receive Ack frame */
#define E1000_IMS_MNG       E1000_ICR_MNG       /* Manageability event */
#define E1000_IMS_RXQ0      E1000_ICR_RXQ0
#define E1000_IMS_RXQ1      E1000_ICR_RXQ1
#define E1000_IMS_TXQ0      E1000_ICR_TXQ0
#define E1000_IMS_TXQ1      E1000_ICR_TXQ1
#define E1000_IMS_OTHER     E1000_ICR_OTHER
#define E1000_IMS_DOCK      E1000_ICR_DOCK      /* Dock/Undock */
#define E1000_IMS_RXD_FIFO_PAR0 E1000_ICR_RXD_FIFO_PAR0 /* queue 0 Rx descriptor FIFO parity error */
#define E1000_IMS_TXD_FIFO_PAR0 E1000_ICR_TXD_FIFO_PAR0 /* queue 0 Tx descriptor FIFO parity error */
#define E1000_IMS_HOST_ARB_PAR  E1000_ICR_HOST_ARB_PAR  /* host arb read buffer parity error */
#define E1000_IMS_PB_PAR        E1000_ICR_PB_PAR        /* packet buffer parity error */
#define E1000_IMS_RXD_FIFO_PAR1 E1000_ICR_RXD_FIFO_PAR1 /* queue 1 Rx descriptor FIFO parity error */
#define E1000_IMS_TXD_FIFO_PAR1 E1000_ICR_TXD_FIFO_PAR1 /* queue 1 Tx descriptor FIFO parity error */
#define E1000_IMS_DSW       E1000_ICR_DSW
#define E1000_IMS_PHYINT    E1000_ICR_PHYINT
#define E1000_IMS_EPRST     E1000_ICR_EPRST

/* Interrupt Mask Clear */
#define E1000_IMC_TXDW      E1000_ICR_TXDW      /* Transmit desc written back */
#define E1000_IMC_TXQE      E1000_ICR_TXQE      /* Transmit Queue empty */
#define E1000_IMC_LSC       E1000_ICR_LSC       /* Link Status Change */
#define E1000_IMC_RXSEQ     E1000_ICR_RXSEQ     /* rx sequence error */
#define E1000_IMC_RXDMT0    E1000_ICR_RXDMT0    /* rx desc min. threshold */
#define E1000_IMC_RXO       E1000_ICR_RXO       /* rx overrun */
#define E1000_IMC_RXT0      E1000_ICR_RXT0      /* rx timer intr */
#define E1000_IMC_MDAC      E1000_ICR_MDAC      /* MDIO access complete */
#define E1000_IMC_RXCFG     E1000_ICR_RXCFG     /* RX /c/ ordered set */
#define E1000_IMC_GPI_EN0   E1000_ICR_GPI_EN0   /* GP Int 0 */
#define E1000_IMC_GPI_EN1   E1000_ICR_GPI_EN1   /* GP Int 1 */
#define E1000_IMC_GPI_EN2   E1000_ICR_GPI_EN2   /* GP Int 2 */
#define E1000_IMC_GPI_EN3   E1000_ICR_GPI_EN3   /* GP Int 3 */
#define E1000_IMC_TXD_LOW   E1000_ICR_TXD_LOW
#define E1000_IMC_SRPD      E1000_ICR_SRPD
#define E1000_IMC_ACK       E1000_ICR_ACK       /* Receive Ack frame */
#define E1000_IMC_MNG       E1000_ICR_MNG       /* Manageability event */
#define E1000_IMC_DOCK      E1000_ICR_DOCK      /* Dock/Undock */
#define E1000_IMC_RXD_FIFO_PAR0 E1000_ICR_RXD_FIFO_PAR0 /* queue 0 Rx descriptor FIFO parity error */
#define E1000_IMC_TXD_FIFO_PAR0 E1000_ICR_TXD_FIFO_PAR0 /* queue 0 Tx descriptor FIFO parity error */
#define E1000_IMC_HOST_ARB_PAR  E1000_ICR_HOST_ARB_PAR  /* host arb read buffer parity error */
#define E1000_IMC_PB_PAR        E1000_ICR_PB_PAR        /* packet buffer parity error */
#define E1000_IMC_RXD_FIFO_PAR1 E1000_ICR_RXD_FIFO_PAR1 /* queue 1 Rx descriptor FIFO parity error */
#define E1000_IMC_TXD_FIFO_PAR1 E1000_ICR_TXD_FIFO_PAR1 /* queue 1 Tx descriptor FIFO parity error */
#define E1000_IMC_DSW       E1000_ICR_DSW
#define E1000_IMC_PHYINT    E1000_ICR_PHYINT
#define E1000_IMC_EPRST E1000_ICR_EPRST



/* Transmit Descriptor */
struct e1000_tx_desc {
    uint64_t buff_addr;  /* data buffer address */
    uint16_t length;     /* data buffer length */
    uint8_t  cso;        /* checksum offset */
    uint8_t  cmd;        /* descriptor control */
    uint8_t  sta;        /* descriptor status */
    uint8_t  css;        /* checksum start */
    uint16_t special;    
};

/* Transmit Descriptor bit definitions */
#define E1000_TXD_CMD_EOP    0x01 /* End of Packet */
#define E1000_TXD_CMD_RS     0x08 /* Report Status */
#define E1000_TXD_STA_DD     0x01 /* Descriptor Done */



/* Transmit Control */
#define E1000_TCTL           0x00400    /* Transmit Control - R/W */
#define E1000_TCTL_EN     0x00000002    /* enable */
#define E1000_TCTL_PSP    0x00000008    /* pad short packets */
#define E1000_TCTL_COLD   0x003ff000    /* collision distance */


#define E1000_TIPG           0x00410    /* Transmit Inter-packet Gap - R/W */


/* Receive Control */
#define E1000_RCTL                 0x00100  /* Receive Control - R/W */
#define E1000_RCTL_EN           0x00000002  /* enable */
#define E1000_RCTL_UPE            0x00000008    /* unicast promiscuous enable */
#define E1000_RCTL_MPE            0x00000010    /* multicast promiscuous enab */
#define E1000_RCTL_LPE          0x00000020  /* long packet enable */
#define E1000_RCTL_LBM_NO       0x00000000  /* no loopback mode */
#define E1000_RCTL_LBM_MAC      0x00000040  /* mac loopback mode */
#define E1000_RCTL_LBM_SLP      0x00000080  /* serial loopback mode */
#define E1000_RCTL_LBM_TCVR     0x000000C0  /* tcvr loopback mode */
#define E1000_RCTL_RDMTS_HALF   0x00000000  /* rx desc min threshold size */
#define E1000_RCTL_RDMTS_QUAT   0x00000100
#define E1000_RCTL_RDMTS_EIGTH  0x00000200      
#define E1000_RCTL_MO_SHIFT     12          /* multicast offset shift */
#define E1000_RCTL_MO_0         0x00000000  /* multicast offset */
#define E1000_RCTL_MO_1         0x00001000
#define E1000_RCTL_MO_2         0x00002000
#define E1000_RCTL_MO_3         0x00003000
#define E1000_RCTL_BAM          0x00008000  /* broadcast enable */ 
#define E1000_RCTL_SZ_2048      0x00000000  /* rx buffer size 2048 */ 
#define E1000_RCTL_BSEX         0x02000000  /* buffer size extension */
#define E1000_RCTL_SECRC        0x04000000  /* strip ethernet crc */

#define E1000_RAL0           0x05400   /* Receive Address Low  - R/W */
#define E1000_RAH0           0x05404   /* Receive Adreess High - R/W */

#define E1000_RDBAL          0x02800   /* Receive Descriptor Base Low  - R/W */
#define E1000_RDBAH          0x02804   /* Receive Descriptor Base High - R/W */
#define E1000_RDLEN          0x02808   /* Receive Descriptor Length    - R/W */
#define E1000_RDH            0x02810   /* Receive Descriptor Head      - R/W */
#define E1000_RDT            0x02818   /* Receive Descriptor Tail      - R/W */


/* Receive Descriptor */
struct e1000_rx_desc {
    uint64_t buff_addr;   /* data buffer address */
    uint16_t length;      /* data buffer length */
    uint16_t csm;         /* packet checksum */
    uint8_t  sta;         /* descriptor status */
    uint8_t  err;         /* descriptor errors */
    uint16_t special;
};

/* Receive Descriptor bit definitions */
#define E1000_RXD_STA_DD     0x01 /* Descriptor Done */
#define E1000_RXD_STA_EOP    0x02 /* End of Packet */


volatile uint32_t *e1000_memreg_vaddr;   /* weak symbol, initialized in pci.c */  

#define E1000_REG(offset) e1000_memreg_vaddr[(offset)/4]

#define ETHERNET_PACKET_SIZE  1518 

int e1000_tx_init(void);
int e1000_rx_init(void);
int e1000_transmit(const void *data, size_t len);
void e1000_receive();

#endif	// JOS_KERN_E1000_H
