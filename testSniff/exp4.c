#include <pcap.h>
#include <time.h>
#include <stdio.h>
#include <stdlib.h>
#include <netinet/if_ether.h>
 
 
void processPacket(u_char *arg, const struct pcap_pkthdr *pkthdr, const u_char *packet)
{
    int *count = (int *)arg;
 
    printf("Packet Count: %d\n", ++(*count));
    printf("Received Packet Size: %d\n", pkthdr->len);
    printf("Payload:\n");
 
    for(int i=0; i < pkthdr->len; ++i)
    {
        printf("%02x ", packet[i]);
        if ((i + 1) % 16 == 0)
        {
            printf("\n");
        }
    }
    printf("\n\n");
    return;
}
 
int main()
{
    char errBuf[PCAP_ERRBUF_SIZE], * devStr;
  
    devStr = pcap_lookupdev(errBuf);
    if (devStr)
        printf("success: device: %s\n", devStr);
    else
    {
        printf("error: %s\n", errBuf);
        exit(1);
    }
 
    /* open a device, wait until a packet arrives */
    pcap_t * device = pcap_open_live(devStr, 65535, 1, 0, errBuf);
    if (!device)
    {
        printf("error: pcap_open_live(): %s\n", errBuf);
        exit(1);
    }
 
    int count = 0;
    /*Loop forever & call processPacket() for every received packet.*/
    //pcap_loop(device, -1, processPacket, (u_char *)&count);
    const unsigned char *p_packet_content = NULL; // 保存接收到的数据包的起始地址
    pcap_t *pcap_handle = NULL;
    struct pcap_pkthdr protocol_header;
 while(1){
    p_packet_content = pcap_next(device, &protocol_header); 
    //p_packet_content  所捕获数据包的地址
		
    printf("Capture Time is :%s",ctime((const time_t *)&protocol_header.ts.tv_sec)); // 时间
    printf("Packet Lenght is :%d\n",protocol_header.len);	// 数据包的实际长度
 
// 分析以太网中的 源mac、目的mac
    struct ethhdr *ethernet_protocol = NULL;
    unsigned char *p_mac_string = NULL;			// 保存mac的地址，临时变量
 
    ethernet_protocol = (struct ethhdr *)p_packet_content;  //struct ether_header 以太网帧头部
 
    p_mac_string = (unsigned char *)ethernet_protocol->h_source;//获取源mac
    printf("Mac Source Address is %02x:%02x:%02x:%02x:%02x:%02x\n",*(p_mac_string+0),*(p_mac_string+1),*(p_mac_string+2),*(p_mac_string+3),*(p_mac_string+4),*(p_mac_string+5));
 
    p_mac_string = (unsigned char *)ethernet_protocol->h_dest;//获取目的mac
    printf("Mac Destination Address is %02x:%02x:%02x:%02x:%02x:%02x\n",*(p_mac_string+0),*(p_mac_string+1),*(p_mac_string+2),*(p_mac_string+3),*(p_mac_string+4),*(p_mac_string+5));

}
    pcap_close(device);
    return 0;
}

