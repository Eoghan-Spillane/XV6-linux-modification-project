//
// network system calls.
//
#define uint8 uint8_t
#define uint16 uint16_t
#define uint32 uint32_t
#define uint64 uint32_t // no 64 bit addresses on x86 use 32bit

#include "types.h"
#include "param.h"
#include "mmu.h"
#include "x86.h"
#include "memlayout.h"
#include "memlayout.h"
#include "spinlock.h"
#include "proc.h"
#include "defs.h"
#include "fs.h"
#include "sleeplock.h"
#include "file.h"
#include "net.h"

struct sock {
  struct sock *next; // the next socket in the list
  uint32 raddr;      // the remote IPv4 address
  uint16 lport;      // the local UDP port number
  uint16 rport;      // the remote UDP port number
  struct spinlock lock; // protects the rxq
  struct mbufq rxq;  // a queue of packets waiting to be received
};

static struct spinlock lock;
static struct sock *sockets;

void
sockinit(void)
{
  initlock(&lock, "socktbl");
}

int
sockalloc(struct file **f, uint32 raddr, uint16 lport, uint16 rport)
{
  struct sock *si, *pos;

  si = 0;
  *f = 0;
  if ((*f = filealloc()) == 0)
    goto bad;
  if ((si = (struct sock*)kalloc()) == 0)
    goto bad;

  cprintf("sock allocated add %x lp %d rp %d\n",raddr,lport,rport);
  // initialize objects
  si->raddr = raddr;
  si->lport = lport;
  si->rport = rport;
  initlock(&si->lock, "sock");
  mbufq_init(&si->rxq);
  (*f)->type = FD_SOCK;
  (*f)->readable = 1;
  (*f)->writable = 1;
  (*f)->sock = si;

  // add to list of sockets
  acquire(&lock);
  pos = sockets;
  while (pos) {
    if (pos->raddr == raddr &&
        pos->lport == lport &&
	pos->rport == rport) {
      release(&lock);
      goto bad;
    }
    pos = pos->next;
  }
  si->next = sockets;
  sockets = si;
  cprintf("added to sockets %x lp %d rp %d\n",si->raddr,si->lport,si->rport);
  release(&lock);
  return 0;

bad:
  if (si)
    kfree((char*)si);
  if (*f)
    fileclose(*f);
  return -1;
}

//
// Your code here.
//
// Add and wire in methods to handle closing, reading,
// and writing for network sockets.
//
void
sockclose(struct sock *si)
{struct sock  *pos,*prev;
if (!si) return;
acquire(&lock);
	  prev = pos = sockets;
	  while (pos) {
	    if (pos->raddr == si->raddr &&
	        pos->lport == si->lport &&
		pos->rport == si->rport) {
	      struct mbuf*m;
	      while ((m=mbufq_pophead(&si->rxq)))
	    	  mbuffree(m);
	      if (pos == sockets)
	    	  sockets = pos->next;
	      else
	    	  prev->next = pos->next;
	      cprintf("sockclose ra %x lp %d rp %d\n",si->raddr,si->lport,si->rport);
	      kfree((char*)si);
	      release(&lock);
	      return;
	    }
	    prev=pos;
	    pos = pos->next;
	  }
	  release(&lock);
}
void
net_tx_udp(struct mbuf *m, uint32 dip,
           uint16 sport, uint16 dport);
int
sockwrite(struct sock *si, char* addr, int n)
{
  struct mbuf *m;
  //struct proc *pr = myproc();

  acquire(&si->lock);




     m = mbufalloc(MBUF_DEFAULT_HEADROOM);
     if (!m){
    	 release(&si->lock);
       return -1;
     }
    memmove(m->head,addr,n);
    //if(copyin(pr->pagetable, m->head, addr, n) == -1)
    //  return -1;
    m->len = n;
    cprintf("net_tx_udp ra %x lp %d rp %d\n",si->raddr,si->lport,si->rport);
    net_tx_udp(m,si->raddr,si->lport,si->rport);
 // }
  release(&si->lock);
  return n;
}

int
sockread(struct sock *si, char *addr, int n)
{

  //struct proc *pr = myproc();

  acquire(&si->lock);
  while(mbufq_empty(&si->rxq)){  //DOC: pipe-empty
    if(myproc()->killed){
      release(&si->lock);
      return -1;
    }
    sleep(&si->rxq, &si->lock); //DOC: piperead-sleep
  }

  struct mbuf * mp = mbufq_pophead(&si->rxq);
  if (!mp){
	  release(&si->lock);
	  return 0;
  }
  cprintf("sock read got some data %d\n",mp->len);
  int retval = n;
  if (n<mp->len){
	  memmove(addr, mp->head,n); // copyout(pr->pagetable, addr, mp->head, n);
	  mbufpull(mp, n);
	  mbufq_pushhead(&si->rxq, mp);
  }
  else{
	  memmove(addr, mp->head,mp->len); //copyout(pr->pagetable, addr, mp->head, mp->len);
	  retval = mp->len;
	  mbuffree(mp);
  }
  release(&si->lock);
  return retval;
}
// called by protocol handler layer to deliver UDP packets
void
sockrecvudp(struct mbuf *m, uint32 raddr, uint16 lport, uint16 rport)
{
  //
  // Your code here.
  //
  // Find the socket that handles this mbuf and deliver it, waking
  // any sleeping reader. Free the mbuf if there are no sockets
  // registered to handle it.
  //
	 acquire(&lock);
	 struct sock *pos;
	 pos = sockets;
	 cprintf("check ra %x lp %d rp %d\n",raddr,lport,rport);
	  while (pos) {
		  cprintf("loop ra %x lp %d rp %d\n",pos->raddr,pos->lport,pos->rport);
	    if (pos->raddr == raddr &&
	        pos->lport == lport &&
		pos->rport == rport) {
cprintf("calling mbufq_pushtail ra %x lp %x rp %x\n",pos->raddr,lport,rport);
	      mbufq_pushtail(&pos->rxq,m);
	      wakeup(&pos->rxq);
		  release(&lock);
          return;
	    }
	    pos = pos->next;
	  }
cprintf("no match ra %x lp %d rp %d\n",raddr,lport,rport);
  release(&lock);
  //mbuffree(m);
}
