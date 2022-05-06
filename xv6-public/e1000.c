#define uint8 uint8_t
#define uint16 uint16_t
#define uint32 uint32_t
#define uint64 uint32_t // no 64 bit addresses on x86 use 32bit

#include "types.h"
#include "defs.h"
#include "e1000.h"
#include "assert.h"
#include "error.h"
#include "memlayout.h"
#include "traps.h"
#include "net.h"
#define printf cprintf

#define NTXDESC  16
static struct e1000_tx_desc tx_queue[NTXDESC] __attribute__ ((aligned(16)));

#define TX_PKT_BUFF_SIZE ETHERNET_PACKET_SIZE
static char tx_buffs[NTXDESC][TX_PKT_BUFF_SIZE];

#define NRXDESC  128
static struct e1000_rx_desc rx_queue[NRXDESC] __attribute__ ((aligned(16)));

#define RX_PKT_BUFF_SIZE 2048
static char rx_buffs[NRXDESC][RX_PKT_BUFF_SIZE];

uint8_t mac_addr[6];

int e1000_tx_init(void) {
    int i;
    
    // Check if alignment requirements are satisfied  
    assert(sizeof(struct e1000_tx_desc) == 16);
    assert(((uint32_t)(&tx_queue[0]) & 0xf) == 0);
    assert(sizeof(tx_queue) % 128 == 0);
	
    // Initialize packet buffers
    memset(tx_queue, 0, sizeof(tx_queue));
    for (i = 0; i < NTXDESC; i++) 
        tx_queue[i].buff_addr = V2P(tx_buffs[i]);
    
    // Initialize regs of transmit descriptor ring (a.k.a. transmit queue)
    E1000_REG(E1000_TDBAL) = V2P(tx_queue); 
    E1000_REG(E1000_TDBAH) = 0;
    E1000_REG(E1000_TDLEN) = sizeof(tx_queue);
    E1000_REG(E1000_TDH)   = 0;
    E1000_REG(E1000_TDT)   = 0;
    
    // Program TCTL & TIPG
    //#define E1000_TCTL           0x00400    /* Transmit Control - R/W */
    //#define E1000_TCTL_EN     0x00000002    /* enable */
    //#define E1000_TCTL_PSP    0x00000008    /* pad short packets */
    //#define E1000_TCTL_COLD   0x003ff000    /* collision distance */
    E1000_REG(E1000_TCTL) |= E1000_TCTL_EN;
    E1000_REG(E1000_TCTL) |= E1000_TCTL_PSP;

    E1000_REG(E1000_TCTL) &= ~E1000_TCTL_COLD;
    E1000_REG(E1000_TCTL) |= 0x00040000; // TCTL.COLD: 40h

    E1000_REG(E1000_TIPG)  = 10;
    
    return 0;
}

int e1000_rx_init(void){
    int i;
    memset(rx_queue, 0, sizeof(rx_queue));
    for (i = 0; i < NRXDESC; i++)
        rx_queue[i].buff_addr = V2P(rx_buffs[i]);
    
    // configure the Receive Adress Registers with the card's 
    // own MAC address ( 52:54:00:12:34:56 ) in order to accept
    // packets addressed to the card
    E1000_REG(E1000_RAL0)  = 0x12005452;
    E1000_REG(E1000_RAH0)  = 0x80005634;   
    uint32_t macaddr_l = E1000_REG(E1000_RAL0);
    uint32_t macaddr_h = E1000_REG(E1000_RAH0);
    *(uint32_t*)mac_addr = macaddr_l;
    *(uint16_t*)(&mac_addr[4]) = (uint16_t)macaddr_h;
    *(uint32_t*)mac_addr = macaddr_l;
    *(uint32_t*)(&mac_addr[4]) = (uint16_t)macaddr_h; 

    // initialize regs of receive descriptor ring
    E1000_REG(E1000_RDBAL) = V2P(rx_queue); 
    E1000_REG(E1000_RDBAH) = 0;
    E1000_REG(E1000_RDLEN) = sizeof(rx_queue);
    E1000_REG(E1000_RDH)   = 0;
    E1000_REG(E1000_RDT)   = NRXDESC - 1;
    
    // enable receive
    E1000_REG(E1000_RCTL) |= E1000_RCTL_EN;
    
    // configure e1000 to strip the Ethernet CRC
    E1000_REG(E1000_RCTL) |= E1000_RCTL_SECRC;

    E1000_REG(E1000_RCTL) |= E1000_RCTL_UPE;    /* unicast promiscuous enable */
    E1000_REG(E1000_RCTL) |= E1000_RCTL_MPE;
     
    return 0;
}

int e1000_transmit(const void *data, size_t len) {
    uint32_t tail = E1000_REG(E1000_TDT);

    if (len > TX_PKT_BUFF_SIZE)
        return -E_PKT_TOO_LONG;	

    if ((tx_queue[tail].cmd & E1000_TXD_CMD_RS) 
        && !(tx_queue[tail].sta & E1000_TXD_STA_DD))
        return -E_TX_FULL;

    memcpy(tx_buffs[tail], data, len);
    tx_queue[tail].length = len;
    tx_queue[tail].cmd |= E1000_TXD_CMD_RS | E1000_TXD_CMD_EOP;
    tx_queue[tail].sta &= ~E1000_TXD_STA_DD;

    E1000_REG(E1000_TDT) = (tail + 1) % NTXDESC;
   
    return 0;
}


struct ethernet_h{
    //	unsigned char preamble[7];
    //	unsigned char delimiter;

    unsigned char destAddress[6];
	unsigned char srcAddress[6];
    // if value < 1500(max allowed frame size); specifies length - ver802.2
    // else value > 1536; specifies which protocol is encapsulated in the payload - Ethernet II framing
    unsigned char etherType[2];
};

struct ip_h
{
    /*need these to compute packet lengths*/
    unsigned char v_ihl; //internet header length
    unsigned char service; //Type of service - used to define the way routers handle the datagram
    unsigned char total_len[2]; //16 bits, max packet size - 2^16 - 65,536
    unsigned char identification[2]; //Used along with src address to uniquely id a datagram
    unsigned char offset[2]; // 00000xxx {Reserved = 0, Don't Fragment, Fragment} 00000000
    unsigned char ttl; //no. of hops
    unsigned char protocol; //http://bit.ly/c0xBMt list of ip protocols
    unsigned char checksum[2];
    unsigned char srcAddress[4];
    unsigned char destAddress[4];
};


struct tcp_h{
	unsigned char src_port[2];
	unsigned char dest_port[2];
	unsigned char seq_num[4];
	unsigned char ack[4];
	unsigned char offset_res_flag[2];
	unsigned char window_size[2];
	unsigned char check_sum[2];
	unsigned char urgent[2];
	unsigned char option[4];		//this char just indicates the first 4 bytes of the optional section. We me need to have a
};

struct tls_h{
	unsigned char type;
	unsigned char version[2];
	unsigned char length[2];
};


void parse1(char *packet, int len){
    int  j;
    printf("len =%d\n",len);

    /*Header Structs*/
    struct eth * ethernet;
    struct ip_h * ip;
    // struct tcp_h * tcp;
    // struct arp * arp;


    /*ethernet header memory map*/
    ethernet = (struct eth *)(packet);

    // Print out packet data
    // Distuinguish between UDP, ARP, TCP
    // IP layer - Parse Source and Destination

    printf("\n\n<-------->Packet Start<-------->");
    printf("\n\t<----> Mac <---->");
    printf("\n\tMAC Source:\t");
        for(j=0;j<6;j++){
            printf("%d:", (int) ethernet->shost[j]);
        }
    printf("\n\tMAC Destination:\t");
        for(j=0;j<6;j++){
            printf("%d:", (int) ethernet->dhost[j]);
        }

    printf("\n\tMAC Destination:\t %d", (int)ethernet->type);

    // ARP
    if(ethernet->type > 1536){
        printf("\n\tEthernet Packet Type:\tARP");
        printf("\n\t<----> ARP <---->");
        
    }
    
    // IP
    if(ethernet->type < 1500){
        printf("\n\tEthernet Packet Type:\tIP\n");
        ip = (struct ip_h  *)(packet + sizeof(struct eth));
        
        printf("\n\t<----> IP <---->");
        printf("\n\tIP Source:\t");
        for(j=0;j<4;j++){
            printf("%d:", ip->srcAddress[j]);
        }
        printf("\n\tIP Destination:\t");
        for(j=0;j<4;j++){
            printf("%d:", ip->destAddress[j]);
        }

        // Specify TCP or UDP
        if(ip->protocol == IPPROTO_TCP){
            printf("\n\tIP Type: TCP\n");
            printf("\n\t<----> TCP <---->");
        }
        if(ip->protocol == IPPROTO_UDP){
            printf("\n\tIP Type: UDP\n");
            printf("\n\t<----> UDP <---->");
        }
    }

    printf("\n<-------->Packet End<-------->\n\n\n");
}

void net_rx(struct mbuf *m);
void e1000_receive(){
    uint32_t tail;
    uint32_t next;
    int len;
    struct mbuf *m;
    while (1){
        tail = E1000_REG(E1000_RDT);
        next = (tail + 1) % NRXDESC;
        if (!(rx_queue[next].sta & E1000_RXD_STA_DD))
            return;
    
        len = rx_queue[next].length;
        //if (size < len)
        //  return -E_PKT_TOO_LONG;

        m = mbufalloc(0);
        m->len = len;
            
        parse1((char *)rx_buffs[next],len);

        memcpy(m->head, rx_buffs[next], len);
        rx_queue[next].sta &= ~E1000_RXD_STA_DD;

        E1000_REG(E1000_RDT) = next;
        cprintf("\ncall net_rx %p",m);
        net_rx(m);
    }
}

int e1000_init(){
	E1000_REG(E1000_IMS) = E1000_IMS_RXT0;
	ioapicenable(IRQ_ETH, 0);
	return 1;
}
void ethintr(){
    E1000_REG(E1000_ICR);
	E1000_REG(E1000_IMS) = E1000_IMS_RXT0;
    e1000_receive();
}
