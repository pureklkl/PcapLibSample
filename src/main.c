//Author: Yuanfan Peng Sep. 10th 2018
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
#include <unistd.h>

#define UNUSED(x) (void)(x)

sigset_t set;

typedef struct PcapInfo {
    int descr;
    long packetCnt; 
    long volume; // in byte
}PcapInfo;

typedef struct OutputInfo {
   int id;
   unsigned char * buffer;
   size_t curSize;
}OutputInfo;

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
  close(pcapInfo->descr);
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

void * output(void* args) {
  OutputInfo* outputInfo = (OutputInfo *)args;
  char buffer[20];
  sprintf(buffer, "./o/%d", outputInfo->id);
  FILE *fp = fopen(buffer, "wb");
  fwrite(outputInfo->buffer, 1, outputInfo->curSize, fp);
  free(outputInfo->buffer);
  free(outputInfo);
  fclose(fp);
  return NULL;
}

int main()
{ 
    int PER_OUTPUT_SIZE = 1024 * 1024 * 1; // MB
    PcapInfo pcapInfo;  
    int data_size;
    struct sockaddr saddr;
    socklen_t saddr_size = sizeof(saddr);     
    pthread_t monitorTh;
    pthread_t outputTh;
    int id = 0;
    OutputInfo* outputInfo = (OutputInfo *)malloc(sizeof(outputInfo));
    outputInfo->buffer = (unsigned char *) malloc(PER_OUTPUT_SIZE); //Its Big!
    outputInfo->curSize = 0;
    outputInfo->id = id;      


    int sock_raw = socket( AF_PACKET , SOCK_RAW , htons(ETH_P_ALL)) ;
     
    if(sock_raw < 0)
    {
        //Print the error with proper message
        perror("Socket Error");
        return 1;
    }

    
    pcapInfo.descr = sock_raw;
    pcapInfo.volume = 0L;
    pcapInfo.packetCnt = 0L; 
    setQuitMonitor(&monitorTh, &pcapInfo);
    
    while(1)
    {
        //Receive a packet
        data_size = recvfrom(sock_raw , outputInfo->buffer + outputInfo->curSize, PER_OUTPUT_SIZE - outputInfo->curSize, 0 , &saddr , &saddr_size);

        if(data_size <0 )
        {
            printf("Recvfrom error , failed to get packets\n");
            break;
        }
        outputInfo->curSize += data_size;
        if (PER_OUTPUT_SIZE - outputInfo->curSize < 1500) {
            pthread_create(&outputTh, NULL, output, outputInfo);
            //pthread_detach(outputTh);
 	
	    outputInfo = (OutputInfo *)malloc(sizeof(outputInfo));
    	    outputInfo->buffer = (unsigned char *) malloc(PER_OUTPUT_SIZE); //Its Big!
    	    outputInfo->curSize = 0;
    	    outputInfo->id = ++id;      
	}
        pcapInfo.packetCnt++;
        pcapInfo.volume += data_size;
    }
    output(outputInfo);
    return 0;
}
