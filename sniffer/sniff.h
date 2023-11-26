#ifndef SNIFF_H
#define SNIFF_H

#include <QThread>
#include <iostream>
#include <QtWidgets/QListWidget>
#include <QLabel>
#include <QDateTime>

using namespace std;
extern "C" {
    #include<stdio.h>
    #include<stdlib.h>
    #include<string.h>
    #include<pcap.h>
    #include<unistd.h>
    #include<string.h>
    #include<ctype.h>
    #include<netdb.h>
    #include<sys/file.h>
    #include<sys/time.h>
    #include<time.h>
    #include <sys/socket.h>
    #include <sys/ioctl.h>
    #include<sys/signal.h>
    #include <net/if.h>
    #include <arpa/inet.h>
    #include <netinet/in.h>
    #include <netinet/ip.h>
    #include <netinet/tcp.h>
    #include <netinet/udp.h>
    #include <netinet/if_ether.h>
    //#include <linux/if_arp.h>
    #include <linux/ipv6.h>
    #include <linux/icmp.h>
}

#define START   1
#define END     0
#define MAXDATAGRAM 50
typedef uint32_t __be;

enum protocol {
    ALL =0,
    ICMP=1,
    IP  =4,
    //IPV6
    //ARP
    TCP =6,
    UDP =17,
    IPV6=41
};
//protocol ref: https://blog.csdn.net/qwrdxer/article/details/109188336

// ref: https://blog.csdn.net/fangxin205/article/details/54613226
// ref: https://blog.csdn.net/hanbo622/article/details/36390031
// ref: https://chegva.com/3298.html

typedef ethhdr myMAChdr;
/*
struct  ethhdr{
     unsigned  char  h_dest[ETH_ALEN];  //目的MAC地址
     unsigned  char  h_source[ETH_ALEN];  //源MAC地址
     __u16 h_proto ;  //网络层所使用的协议类型
}__attribute__((packed))   //用于告诉编译器不要对这个结构体中的缝隙部分进行填充操作；
*/

typedef iphdr myIPhdr;
/*
struct iphdr {
    __u8	ihl:4,              //首部长度
    __u8	version:4,          //版本号
    __u8	tos;                //服务类型字段
    __be16	tot_len;            //总长度   （需要进行字节调整
    __be16	id;                 //标识   （需要进行字节调整
    __be16	frag_off;           //标志与片偏移   （需要进行字节调整
    __u8	ttl;                //生存时间
    __u8	protocol;           //协议
    __sum16	check;              //检验和   （需要进行字节调整
    __be32	saddr;              //源地址
    __be32	daddr;              //目的地址
};
*/

typedef ipv6hdr myIPV6hdr;
/*
struct ipv6hdr {
#if defined(__LITTLE_ENDIAN_BITFIELD)
    __u8			priority:4,
                version:4;
#elif defined(__BIG_ENDIAN_BITFIELD)
    __u8			version:4,
                priority:4;
#else
#error	"Please fix <asm/byteorder.h>"
#endif
    __u8			flow_lbl[3];

    __be16			payload_len;
    __u8			nexthdr;
    __u8			hop_limit;
    struct	in6_addr	saddr;
    struct	in6_addr	daddr;
};
*/

typedef tcphdr myTCPhdr;
/*
struct tcphdr {
    __be16  source;//16位源端口号
    __be16  dest;//16位目的端口号
    __be32  seq;
    __be32  ack_seq;
#if defined(__LITTLE_ENDIAN_BITFIELD)
    __u16   res1:4,//保留位
        doff:4,// tcp头长度
        fin:1,
        syn:1,
        rst:1,
        psh:1,
        ack:1,
        urg:1,
        ece:1,
        cwr:1;
#elif defined(__BIG_ENDIAN_BITFIELD)
    __u16   doff:4,
        res1:4,
        cwr:1,
        ece:1,
        urg:1,
        ack:1,
        psh:1,
        rst:1,
        syn:1,
        fin:1;
#else
#error  "Adjust your <asm/byteorder.h> defines"
#endif
    __be16  window;//16位滑动窗口的大小
    __sum16 check;//tcp校验和
    __be16  urg_ptr;
};
*/

typedef udphdr myUDPhdr;
/*
struct udphdr{
   u_int16_t source;         // 源端口号
   u_int16_t dest;             // 目的端口号
   u_int16_t len;               // 长度
   u_int16_t check;          // 校验和
};
*/

typedef arphdr myARPhdr;
/*
struct  arphdr{
    unsigned  short  int  ar_hrd;                        // 硬件类型
    unsigned  short  int  ar_pro;                        //  协议类型
    unsigned  char  ar_hln;                                // 硬件地址长度
    unsigned  char  ar_pln;                                // 协议地址长度
    unsigned  short  int  ar_op;                          // ARP命令
# if  1
 //Ethernet  looks  like  this  :  This  bit  is  variable  sized  however..
    unsigned  char  __ar_sha[ETH_ALEN];       // 发送端以太网地址
    unsigned  char  __ar_sip[4];                        // 发送端IP地址
    unsigned  char  __ar_tha[ETH_ALEN];       // 目的以太网地址
    unsigned  char  __ar_tip[4];                         // 目的IP地址
# endif
};
*/

typedef icmphdr myICMPhdr;
/*
struct icmphdr {
  __u8		type;//报文类型
  __u8		code;//报文类型进一步信息
  __sum16	checksum;
  union {
    struct {
        __be16	id;
        __be16	sequence;
    } echo;
    __be32	gateway;
    struct {
        __be16	__unused;
        __be16	mtu;
    } frag;
    __u8	reserved[4];
  } un;
};
*/

class Sniff : public QThread
{
    Q_OBJECT
public:
    explicit Sniff(QObject *parent = 0);
    void setW(QListWidget *_list_lw, QLabel *_load_lb);
    void run();
    void startsniff(int _filter);
    void stop();
    char data_li[MAXDATAGRAM][4096];
    void setFilter(int _filter);
    void processPacket(u_char *arg, const struct pcap_pkthdr *pkthdr, const u_char *packet);
    QString getProtocol(int protocol);

private:
    char errBuf[PCAP_ERRBUF_SIZE], * devStr;
    pcap_t * device;
    int count = 0;

    int sock;
    struct ifreq ethreq;
    int n;
    struct ethhdr *macheader;
    struct iphdr *ipheader;
    //struct myIPhdr *ipheader;
    //struct myMAChdr *macheader;
    int state;
    int filter;

    QListWidget *list_lw;
    QLabel *load_lb;

};

#endif // SNIFF_H
