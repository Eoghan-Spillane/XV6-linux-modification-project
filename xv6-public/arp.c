

#include "types.h"
#include "defs.h"
#include "arp_frame.h"
int 
e1000_receive(void *buff, size_t size);
void parse(char *packet);

static int block_until_arp_reply(struct ethr_hdr *arpReply) {
  /**
   *TODO: repeated sleep. wake up on each network interrupt.
   *      check for ARP reply for this request.
   *      If received, unblock. else, sleep again.
   */
  char buff[1000]; 
int cnt =0;
do{
while (e1000_receive((void *)buff, 1000)<0);
cprintf("got packet\n");

cprintf("after parse\n");
cnt++;
}while (cnt <10);

  return 0;
}



int 
e1000_transmit(const void *data, size_t len);
extern uint8_t mac_addr[6];
int send_arpRequest(char* interface, char* ipAddr, char* arpResp) {
  cprintf("Create arp request for ip:%s over Interface:%s\n", ipAddr, interface);

  
  struct ethr_hdr eth;
  
  	
  create_eth_arp_frame(mac_addr, ipAddr, &eth);
  e1000_transmit( (uint8_t*)&eth, sizeof(eth)-2); //sizeof(eth)-2 to remove padding. padding was necessary for alignment.

  struct ethr_hdr arpResponse;
  if(block_until_arp_reply(&arpResponse) < 0) {
    cprintf("ERROR:send_arpRequest:Failed to recv ARP response over the NIC\n");
    return -3;
  }

  unpack_mac(arpResponse.arp_dmac, arpResp);
  arpResp[17] = '\0';

  return 0;
}
