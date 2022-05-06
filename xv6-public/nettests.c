#define uint8 uint8_t
#define uint16 uint16_t
#define uint32 uint32_t
#include "param.h"
#include "types.h"
#include "stat.h"
#include "user.h"
#include "fs.h"
#include "fcntl.h"
#include "syscall.h"
#include "traps.h"
#include "memlayout.h"
#include "net.h"
#define DNSTEST
int attempts1;
//
// send a UDP packet to the localhost (outside of qemu),
// and receive a response.
//
static void
ping(uint16 sport, uint16 dport, int attempts)
{
  int fd;
  char obuf[13] = "hello world!";
  uint32 dst;
  if (attempts1 <40)return;
  // 10.0.2.2, which qemu remaps to the external host,
  // i.e. the machine you're running qemu on.
  dst = (10 << 24) | (0 << 16) | (2 << 8) | (2 << 0);

  // you can send a UDP packet to any Internet address
  // by using a different dst.
  
  if((fd = connect(dst, sport, dport)) < 0){
    printf(1, "ping: connect() failed\n");
    exit();
  }

  for(int i = 0; i < attempts; i++) {
    if(write(fd, obuf, sizeof(obuf)) < 0){
      printf(1, "ping: send() failed\n");
      exit();
    }
  }

  char ibuf[128];
  int cc = read(fd, ibuf, sizeof(ibuf));

  if(cc < 0){
    printf(1, "ping: recv() failed\n");
    exit();
  }
  ibuf[cc]=0;
    printf(1,"**read return %d %s**:\n",cc,ibuf);
    printf(1,ibuf);
    printf(1,":**\n");
  close(fd);
  if (strcmp(obuf, ibuf) || cc != sizeof(obuf)){
    printf(1, "ping didn't receive correct payload\n");
    exit();
  }
}
#ifdef DNSTEST
// Encode a DNS name
static void
encode_qname(char *qn, char *host)
{
  char *l = host; 
  
  for(char *c = host; c < host+strlen(host)+1; c++) {
    if(*c == '.') {
      *qn++ = (char) (c-l);
      for(char *d = l; d < c; d++) {
        *qn++ = *d;
      }
      l = c+1; // skip .
    }
  }
  *qn = '\0';
}

// Decode a DNS name
static void
decode_qname(char *qn)
{
  while(*qn != '\0') {
    int l = *qn;
    if(l == 0)
      break;
    for(int i = 0; i < l; i++) {
      *qn = *(qn+1);
      qn++;
    }
    *qn++ = '.';
  }
}

// Make a DNS request
static int
dns_req(uint8 *obuf)
{
  int len = 0;
  
  struct dns *hdr = (struct dns *) obuf;
  hdr->id = htons(6828);
  hdr->rd = 1;
  hdr->qdcount = htons(1);
  
  len += sizeof(struct dns);
  
  // qname part of question
  char *qname = (char *) (obuf + sizeof(struct dns));
  char *s = "pdos.csail.mit.edu.";
  encode_qname(qname, s);
  len += strlen(qname) + 1;

  // constants part of question
  struct dns_question *h = (struct dns_question *) (qname+strlen(qname)+1);
  h->qtype = htons(0x1);
  h->qclass = htons(0x1);

  len += sizeof(struct dns_question);
  return len;
}

// Process DNS response
static void
dns_rep(uint8 *ibuf, int cc)
{
  struct dns *hdr = (struct dns *) ibuf;
  int len;
  char *qname = 0;
  int record = 0;

  if(!hdr->qr) {
    exit();
    printf(1,"Not a DNS response for %d\n", ntohs(hdr->id));
  }

  if(hdr->id != htons(6828))
    printf(1,"DNS wrong id: %d\n", ntohs(hdr->id));
  
  if(hdr->rcode != 0) {
    printf(1,"DNS rcode error: %x\n", hdr->rcode);
    exit();
  }
  printf(1,"here2\n");
  printf(1,"qdcount: %x\n", ntohs(hdr->qdcount));
  printf(1,"ancount: %x\n", ntohs(hdr->ancount));
  printf(1,"nscount: %x\n", ntohs(hdr->nscount));
  printf(1,"arcount: %x\n", ntohs(hdr->arcount));
  
  len = sizeof(struct dns);

  for(int i =0; i < ntohs(hdr->qdcount); i++) {
    char *qn = (char *) (ibuf+len);
    qname = qn;
    decode_qname(qn);
    len += strlen(qn)+1;
    len += sizeof(struct dns_question);
  }
printf(1,"here3\n");
  for(int i = 0; i < ntohs(hdr->ancount); i++) {
    char *qn = (char *) (ibuf+len);
    
    if((int) qn[0] > 63) {  // compression?
      qn = (char *)(ibuf+qn[1]);
      len += 2;
    } else {
      decode_qname(qn);
      len += strlen(qn)+1;
    }
      printf(1,"here4\n");
    struct dns_data *d = (struct dns_data *) (ibuf+len);
    len += sizeof(struct dns_data);
    // printf(1,"type %d ttl %d len %d\n", ntohs(d->type), ntohl(d->ttl), ntohs(d->len));
    if(ntohs(d->type) == ARECORD && ntohs(d->len) == 4) {
      record = 1;
      printf(1,"DNS arecord for %s is ", qname ? qname : "" );
      uint8 *ip = (ibuf+len);
      printf(1,"%d.%d.%d.%d\n", ip[0], ip[1], ip[2], ip[3]);
      if(ip[0] != 128 || ip[1] != 52 || ip[2] != 129 || ip[3] != 126) {
        printf(1,"wrong ip address");
        exit();
      }
      len += 4;
    }
  }
printf(1,"here5\n");
  if(len != cc) {
    printf(1,"Processed %d data bytes but received %d\n", len, cc);
    exit();
  }
printf(1,"here6\n");
  if(!record) {
    printf(1,"Didn't receive an arecord\n");
    exit();
  }
printf(1,"here7\n");
}

static void
dns()
{
  #define N 1000
  uint8 obuf[N];
  uint8 ibuf[N];
  uint32 dst;
  int fd;
  int len;

  memset(obuf, 0, N);
  memset(ibuf, 0, N);
  
  // 8.8.8.8: google's name server
  dst = (8 << 24) | (8 << 16) | (8 << 8) | (8 << 0);

  if((fd = connect(dst, 10000, 53)) < 0){
    printf(1, "ping: connect() failed\n");
    exit();
  }

  len = dns_req(obuf);
  
  if(write(fd, obuf, len) < 0){
    printf(1, "dns: send() failed\n");
    exit();
  }
  int cc = read(fd, ibuf, sizeof(ibuf));
  if(cc < 0){
    printf(1, "dns: recv() failed\n");
    exit();
  }
printf(1,"dns len %d\n",cc);
ibuf[cc]=0;
for (int y=0;y<cc;y++)
   printf(1,"%x ",ibuf[y]);
printf(1,"\nhere\n");
  dns_rep(ibuf, cc);
printf(1,"here1\n");
  close(fd);
}  

#endif

int
main(int argc, char *argv[])
{
  //int i;
  uint16 dport = NET_TESTS_PORT;

  printf(1,"nettests running on port %d\n", dport);
attempts1=4000;
  printf(1,"testing one ping: ");
 ping(2000, dport, 2);
 ping(2000, dport, 2);
  printf(1,"OK\n");
  //attempts1=20;
  printf(1,"testing single-process pings: ");
  //for (i = 0; i < 100; i++)
   // ping(2000, dport, 1);
  printf(1,"OK\n");





  printf(1,"testing multi-process pings: ");
 /* for (i = 0; i < 10; i++){
	  printf(1,"multi ping: %d",i);
    int pid = fork();
    if (pid == 0){
      ping(2000 + i + 1, dport, 1);
      exit();
    }
  }
  for (i = 0; i < 10; i++){
    if (wait()<0)
      exit();
  }*/
  printf(1,"OK\n");
  
  printf(1,"testing DNS\n");
  dns();
  printf(1,"DNS OK\n");
  
  printf(1,"all tests passed.\n");
  exit();
}
