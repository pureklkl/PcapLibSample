/**********************************************************************
* file:   testpcap3.c
* date:   Sat Apr 07 23:23:02 PDT 2001  
* Author: Martin Casado
* Last Modified:2001-Apr-07 11:23:05 PM
*
* Investigate using filter programs with pcap_compile() and
* pcap_setfilter()
*
**********************************************************************/

#include <pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netinet/if_ether.h> 
#include <signal.h>
#include <pthread.h>

#define UNUSED(x) (void)(x)

sigset_t set;

typedef struct PcapInfo {
    pcap_t* descr;
    long packetCnt; 
    long volume; // in byte
}PcapInfo;

void * quitMonitor(void * args) {
  PcapInfo* pcapInfo = (PcapInfo *)args;
  fprintf(stdout, "quit monitoring\n");
  fflush(stdout);
#if defined(__sun) && defined(__SVR4)
  sigwait(&set);
#else
  int sig; 
  sigwait(&set, &sig);
#endif
  pcap_breakloop(pcapInfo->descr);
  fprintf(stdout, "\n%ld packets, %ld Bytes\n", pcapInfo->packetCnt, pcapInfo->volume);
  fflush(stdout);
  return NULL;
}

void setQuitMonitor(pthread_t* monitorTh, PcapInfo* info) {
  // block signal
  if(sigemptyset(&set) == -1) {
    fprintf(stdout, "fail to init signal set");
  }
  if (sigaddset(&set, SIGINT)) {
    fprintf(stdout, "fail to add siginit");
  }
  if (sigprocmask(SIG_BLOCK, &set, NULL) == -1) {
    fprintf(stdout, "fail to mask signal");
  }
  // start monitor thread
  pthread_create(monitorTh, NULL, quitMonitor, info);
  //pthread_detach(monitorTh);
}


/* print count and volume  */
void my_callback(u_char *args,const struct pcap_pkthdr* pkthdr,const u_char*
        packet)
{
    PcapInfo* pcapInfo = (PcapInfo *)args;
    UNUSED(packet);
    pcapInfo->volume += pkthdr->len;
    pcapInfo->packetCnt++;
}

int main(int argc,char **argv)
{ 
    char *dev; 
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* descr;
    struct bpf_program fp;      /* hold compiled program     */
    bpf_u_int32 maskp;          /* subnet mask               */
    bpf_u_int32 netp;           /* ip                        */
    PcapInfo pcapInfo;
    pthread_t monitorTh;

    if(argc != 2){ fprintf(stdout,"Usage: %s \"filter program\"\n"
            ,argv[0]);return 0;}

    /* grab a device to peak into... */
    dev = pcap_lookupdev(errbuf);
    if(dev == NULL)
    { fprintf(stderr,"%s\n",errbuf); exit(1); }

    /* ask pcap for the network address and mask of the device */
    pcap_lookupnet(dev,&netp,&maskp,errbuf);

    /* open device for reading this time lets set it in promiscuous
     * mode so we can monitor traffic to another machine             */
    descr = pcap_open_live(dev,BUFSIZ,1,-1,errbuf);
    if(descr == NULL)
    { printf("pcap_open_live(): %s\n",errbuf); exit(1); }

    /* Lets try and compile the program.. non-optimized */
    if(pcap_compile(descr,&fp,argv[1],0,netp) == -1)
    { fprintf(stderr,"Error calling pcap_compile\n"); exit(1); }

    /* set the compiled program as the filter */
    if(pcap_setfilter(descr,&fp) == -1)
    { fprintf(stderr,"Error setting filter\n"); exit(1); }
    
    pcapInfo.descr = descr;
    pcapInfo.volume = 0L;
    pcapInfo.packetCnt = 0L; 
    setQuitMonitor(&monitorTh, &pcapInfo);
   
    /* ... and loop */ 
    pcap_loop(descr,-1,my_callback,(u_char *)&pcapInfo);

    return 0;
}
