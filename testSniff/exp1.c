#include<stdio.h>
#include<stdlib.h>
#include<unistd.h>
#include<string.h>
#include<ctype.h>
#include<netdb.h>
#include<sys/file.h>
#include<sys/time.h>
#include<time.h>
#include<sys/socket.h>
#include<sys/ioctl.h>
#include<sys/signal.h>
#include<net/if.h>
#include<arpa/inet.h>
#include<netinet/in.h>
#include<netinet/ip.h>
#include<netinet/tcp.h>
#include<netinet/if_ether.h>

struct ifreq ethreq;
int main(int argc,char *argv[]){
    int sock,n;
    char buffer[4096];
    unsigned char *iphead,*ethhead;
    sock = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    strncpy(ethreq.ifr_name,"ens33",IFNAMSIZ);
    ioctl(sock,SIOCGIFFLAGS,ethreq);
    ethreq.ifr_flags |= IFF_PROMISC;
    ioctl(sock,SIOCGIFFLAGS,ethreq);


    while(1){
        n = recvfrom(sock,buffer,4096,0,NULL,NULL);
        while(n!=-1){
        printf("%d bytes read\n",n);
        ethhead = buffer;

        printf("Source MAC address: %02x:%02x:%02x:%02x:%02x:%02x\n",ethhead[0],ethhead[1],ethhead[2],ethhead[3],ethhead[4],ethhead[5]);
        printf("Destination MAC address: %02x:%02x:%02x:%02x:%02x:%02x\n",ethhead[6],ethhead[7],ethhead[8],ethhead[9],ethhead[10],ethhead[11]);
        iphead = buffer+14; /* Skip Ethernet header */
        if (*iphead== 0x45) { /* Double check for IPv4
                                * and no options present */
            printf("Source host %d.%d.%d.%d\n",iphead[12],iphead[13],iphead[14],iphead[15]);
            printf("Dest host %d.%d.%d.%d\n",iphead[16],iphead[17],iphead[18],iphead[19]);
            printf("Source,Dest ports %d,%d\n",(iphead[20]<<8)+iphead[21],(iphead[22]<<8)+iphead[23]);
            printf("Layer-4 protocol %d\n",iphead[9]);
        }
        }


    }

    return 0;
}
