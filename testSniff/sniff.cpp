#include "sniff.h"

Sniff::Sniff(QObject *parent) : QThread(parent)
{
    sock = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    //设置网卡为混杂模式
    strncpy(ethreq.ifr_name, "eth0", IFNAMSIZ);
    ioctl(sock, SIOCGIFFLAGS, &ethreq);
    ethreq.ifr_flags |= IFF_PROMISC;
    ioctl(sock, SIOCSIFFLAGS, &ethreq);

    state = END;
    filter = ALL;
}

void Sniff::run()
{
    QString path ="";
    QString msg = "sniff...";
    int i=0;
    while(1)
    {
        if(state == START)
        {
            //清空缓存
            bzero(data_li[i], 2048);
            //开始抓包
           n = recvfrom(sock,data_li[i],2048,0,NULL,NULL);
           macheader = (struct ethhdr *) data_li[i];
           ipheader = (struct iphdr *)( data_li[i] + 14);
           //只抓IP 数据包
           if(macheader->h_proto != 8)   continue;
           //过滤器
           if(ipheader->protocol != filter && filter != ALL) continue;
           //显示源ip和目的ip
           char saddr[4], daddr[4];
           memset(saddr, 0,sizeof(char) *  4);
           memset(daddr, 0,sizeof(char) *  4);
           saddr[0] = (char)(0xff & ipheader->saddr);
           saddr[1] = (char)((0xff00 & ipheader->saddr)>>8);
           saddr[2] = (char)((0xff0000 & ipheader->saddr)>>16);
           saddr[3] = (char)((0xff000000 & ipheader->saddr)>>24);
           daddr[0] = (char)(0xff & ipheader->daddr);
           daddr[1] = (char)((0xff00 & ipheader->daddr)>>8);
           daddr[2] = (char)((0xff0000 & ipheader->daddr)>>16);
           daddr[3] = (char)((0xff000000 & ipheader->daddr)>>24);

           path.append(QString("%1: %2.%3.%4.%5->").arg(getProtocol(ipheader->protocol))
                       .arg(QString::number((int)saddr[0]))
                       .arg(QString::number((int)saddr[1]))
                       .arg(QString::number((int)saddr[2]))
                       .arg(QString::number((int)saddr[3])));
           path.append(QString("%1.%2.%3.%4").arg(QString::number((int)daddr[0]))
                       .arg(QString::number((int)daddr[1]))
                       .arg(QString::number((int)daddr[2]))
                       .arg(QString::number((int)daddr[3])));
           //获当前时间
           QDateTime current_date_time = QDateTime::currentDateTime();
           QString current_date = current_date_time.toString(" hh:mm:ss yyyy-MM-dd");
           //显示数据包类型+抓取时间
           path.append(QString("\t  (%1)").arg(current_date));
           //显示
           if(i == 0)   list_lw->clear();
           list_lw->addItem(path);
           path.clear();

           /*由于接收双字节的顺序网络序的，需要调整过来*/
           ipheader->tot_len = (ipheader->tot_len>>8) + (ipheader->tot_len<<8);
           ipheader->id = (ipheader->id>>8) + (ipheader->id<<8);
           ipheader->frag_off = (ipheader->frag_off>>8) + (ipheader->frag_off<<8);
           ipheader->check = (ipheader->check>>8) + (ipheader->check<<8);

           struct icmphdr *icmpheader = (struct icmphdr *)(data_li[i]+14+ipheader->ihl*4);
           struct tcphdr *tcpheader = (struct tcphdr *)(data_li[i]+14+ipheader->ihl*4);
           struct udphdr *udpheader = (struct udphdr *)(data_li[i]+14+ipheader->ihl*4);
           switch(ipheader->protocol)
           {
                case ICMP:
                    /*由于接收双字节的网络序的，需要调整过来*/
                    icmpheader->checksum = (icmpheader->checksum>>8) + (icmpheader->checksum<<8);
                    icmpheader->un.echo.id = (icmpheader->un.echo.id>>8) + (icmpheader->un.echo.id<<8);
                    icmpheader->un.echo.sequence = (icmpheader->un.echo.sequence>>8) + (icmpheader->un.echo.sequence<<8);
                    break;
                case TCP:

                    /*由于接收双字节的网络序的，需要调整过来*/
                    tcpheader->source = (tcpheader->source>>8) + (tcpheader->source<<8);
                    tcpheader->dest = (tcpheader->dest>>8) + (tcpheader->dest<<8);
                    tcpheader->window = (tcpheader->window>>8) + (tcpheader->window<<8);
                    tcpheader->check = (tcpheader->check>>8) + (tcpheader->check<<8);
                    tcpheader->seq = (tcpheader->seq>>24) + ((tcpheader->seq>>8)&0x00ff00)
                                        + ((tcpheader->seq<<8)&0x00ff0000) + (tcpheader->seq<<24);
                    tcpheader->ack_seq = (tcpheader->ack_seq>>24) + ((tcpheader->ack_seq>>8)&0x00ff00)
                                        + ((tcpheader->ack_seq<<8)&0x00ff0000) + (tcpheader->ack_seq<<24);
                    //cout<<"tcp"<<endl;
                    break;
                case UDP:

                    /*由于接收双字节的是网络序的，需要调整过来*/
                    udpheader->source = (udpheader->source>>8) + (udpheader->source<<8);
                    udpheader->dest = (udpheader->dest>>8) + (udpheader->dest<<8);
                    udpheader->len = (udpheader->len>>8) + (udpheader->len<<8);
                    udpheader->check = (udpheader->check>>8) + (udpheader->check<<8);
                    //cout<<"udp"<<endl;
           }
           i++;
           //超最大抓取数，清0
           if(i >= MAXDATAGRAM)
           {
               i = 0;
               msg = "sniff..";
           }
           msg.append(".");
           load_lb->setText(msg);
        }
        else {
            sleep(1);
        }
    }
}

//把类型转成字符串
QString Sniff::getProtocol(int protocol)
{
    switch(protocol)
    {
        case ICMP:
            return "ICMP";
            break;
        case TCP:
            return "TCP";
            break;
        case UDP:
            return "UDP";
    }
    return "UNKNOW";
}

//设置显示控件
void Sniff::setW(QListWidget *_list_lw, QLabel *_load_lb)
{
    list_lw = _list_lw;
    load_lb = _load_lb;
}

//允许抓取
void Sniff::startsniff(int _filter)
{
    setFilter(_filter);
    state = START;
    load_lb->setText("sniff...");
}

//停止抓取
void Sniff::stop()
{
    state = END;
    load_lb->setText("stop");
}

//设置过滤器
void Sniff::setFilter(int _filter)
{
    filter = _filter;
}
