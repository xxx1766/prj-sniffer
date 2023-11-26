#include<stdio.h>
#include<stdlib.h>
#include<string.h>
#include<netinet/ip_icmp.h>
#include<netinet/tcp.h>
#include<netinet/udp.h>
#include<arpa/inet.h>
#include<sys/socket.h>
#include<sys/types.h>
#include<linux/if_ether.h>
#include<arpa/inet.h>
#include <unistd.h>

#define BUFFSIZE 1024

int main(int argc, char *argv[]){

    int rawsock;
    unsigned char buff[BUFFSIZE];
    int n;
    int count = 0;
    char ch;
    char proto[6],
         saddr[20] = {},
         daddr[20] ={},
         address[20]= {};
    int slen = 0;

	
    rawsock = socket(AF_UNIX,SOCK_DGRAM, htons(ETH_P_IP));
    //rawsock = socket(AF_UNIX, SOCK_STREAM, htons(ETH_P_IP));
    if(rawsock < 0){
        printf("raw socket error!\n");
        printf("%d",rawsock);
        exit(1);
    }
    while((ch = getopt(argc, argv, "p:s:d:h")) != -1){
        switch (ch) {
            case 'p':
                slen = strlen(optarg);
                if(slen > 4){
                    fprintf(stdout, "The protocol is error!\n");
                    return -1;
                }
                memcpy(proto, optarg, slen);
                proto[slen] = '\0';
                break;
            case 's':
                slen = strlen(optarg);
                if(slen > 15 || slen < 7){
                    fprintf(stdout, "The IP address is error!\n");
                    return -1;
                }
                memcpy(saddr, optarg, slen);
                saddr[slen] = '\0';
                break;
            case 'd':
                slen = strlen(optarg);
                if(slen > 15 || slen < 7){
                    fprintf(stdout, "The IP address is error!\n");
                    return -1;
                }
                memcpy(daddr, optarg, slen);
                saddr[slen] = '\0';
                break;
            case 'h':
                fprintf(stdout, "usage: snffer [-p protocol] [-s source_ip_address] [-d dest_ip_address]\n"
                                "    -p    protocol[TCP/UDP/ICMP]\n"
                                "    -s    souce ip address\n"
                                "    -d    dest ip address\n");
                exit(0);
            case '?':
                fprintf(stdout, "unrecongized option: %c\n", ch);
                exit(-1);
        }
    }
    while(1){    
        n = recvfrom(rawsock,buff,BUFFSIZE,0,NULL,NULL);
        if(n<0){
            printf("receive error!\n");
            exit(1);
        }

        count++;
        struct ip *ip = (struct ip*)(buff);
        if(strlen(proto)){
            if(!strcmp(proto, "TCP")){
                if(ip->ip_p != IPPROTO_TCP)
                    continue;
                else 
                    goto addr;
            }else if(!strcmp(proto, "UDP")){
                if(ip->ip_p != IPPROTO_UDP)
                    continue;
                else 
                    goto addr;
            }else if(!strcmp(proto, "ICMP")){
                if(ip->ip_p != IPPROTO_ICMP)
                    continue;
                else
                    goto addr;
            }
        }

addr:
        if(strlen(saddr)){
            strcpy(address, inet_ntoa(ip->ip_src));
            if(strcmp(address, saddr) != 0)
                continue;
        }
        if(strlen(daddr)){
            strcpy(address, inet_ntoa(ip->ip_dst));
            if(strcmp(address, daddr) != 0)
                continue;
        }


        printf("%4d    %15s",count,inet_ntoa(ip->ip_src));
        printf("%15s    %5d    %5d\n",inet_ntoa(ip->ip_dst),ip->ip_p,ntohs(ip->ip_len));

        int i=0,j=0;
        for(i=0;i<n;i++){
            if(i!=0 && i%16==0){
                printf("    ");
                for(j=i-16;j<i;j++){
                    if(buff[j]>=32&&buff[j]<=128)
                        printf("%c",buff[j]);
                    else printf(".");
                }
                printf("\n");
            }
            if(i%16 == 0) printf("%04x    ",i);            
            printf("%02x",buff[i]);

            if(i==n-1){
                for(j=0;j<15-i%16;j++) printf("  ");
                printf("    ");
                for(j=i-i%16;j<=i;j++){
                    if(buff[j]>=32&&buff[j]<127)
                        printf("%c",buff[j]);
                    else printf(".");

                }

            }

        }

        printf("\n\n");

    }
}
