#include "sniff.h"
#include <QDebug>
#include <string.h>
Sniff::Sniff(QObject *parent) : QThread(parent){

    state = END;
    filter = ALL;

    devStr = pcap_lookupdev(errBuf);
    if (devStr)
        printf("success: device: %s\n", devStr);
    else
    {
        printf("error: %s\n", errBuf);
        exit(1);
    }
    /* open a device, wait until a packet arrives */
    device = pcap_open_live(devStr, 65535, 1, 0, errBuf);
    if (!device)
    {
        printf("error: pcap_open_live(): %s\n", errBuf);
        exit(1);
    }
    count=0;
}

void Sniff::processPacket(u_char *arg, const struct pcap_pkthdr *pkthdr, const u_char *packet)
{
    int *count = (int *)arg;

    printf("Packet Count: %d\n", ++(*count));
    printf("Received Packet Size: %d, Real Size: %d\n", pkthdr->len, pkthdr->caplen);
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

    QString path ="";
    QString msg = "sniff...";
    int i = 0;

    struct ethhdr *macheader;
    struct iphdr *ipheader;
    macheader = (struct ethhdr *) packet;
    ipheader = (struct iphdr *)( packet + 14);
    printf("MAC protocol: %d\n", macheader->h_proto);
    printf("IP protocol : %d\n", ipheader->protocol);

    while(1) {
        if(Sniff::state == START) {
            //清空缓存
            bzero(data_li[i], 2048);
            //显示
            if(i == 0)
                list_lw->clear();

            //开始抓包
            n = recvfrom(sock, data_li[i], 2048, 0, NULL, NULL);
            qDebug() << "n: " << n;

            macheader = (struct ethhdr *) data_li[i];
            ipheader = (struct iphdr *)( data_li[i] + 14);

            //只抓IP 数据包
            if(macheader->h_proto != 8)
                continue;

            //过滤器
            if(ipheader->protocol != filter && filter != ALL)
                continue;

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

            path.append(QString("%1: %2 . %3 . %4 . %5->").arg(getProtocol(ipheader->protocol))
                        .arg(QString::number((int)saddr[0]))
                        .arg(QString::number((int)saddr[1]))
                        .arg(QString::number((int)saddr[2]))
                        .arg(QString::number((int)saddr[3])));
            path.append(QString("%1 . %2 . %3 . %4").arg(QString::number((int)daddr[0]))
                        .arg(QString::number((int)daddr[1]))
                        .arg(QString::number((int)daddr[2]))
                        .arg(QString::number((int)daddr[3])));
            qDebug() << path;

            //获当前时间
            QDateTime current_date_time = QDateTime::currentDateTime();
            QString current_date = current_date_time.toString(" hh:mm:ss yyyy-MM-dd");
            qDebug() << current_date;

            //显示数据包类型+抓取时间
            path.append(QString("\t  (%1)").arg(current_date));

            list_lw->addItem(path);
            path.clear();

            ///由于接收双字节的顺序网络序的，需要调整过来
            //ipheader->tot_len = (ipheader->tot_len>>8) + (ipheader->tot_len<<8);
            //ipheader->id = (ipheader->id>>8) + (ipheader->id<<8);
            //ipheader->frag_off = (ipheader->frag_off>>8) + (ipheader->frag_off<<8);
            //ipheader->check = (ipheader->check>>8) + (ipheader->check<<8);
            ipheader->tot_len = htons(ipheader->tot_len);
            ipheader->id = htons(ipheader->id);
            ipheader->frag_off = htons(ipheader->frag_off);
            ipheader->check = htons(ipheader->check);

            struct icmphdr *icmpheader = (struct icmphdr *)(data_li[i] +14 +ipheader->ihl*4);
            struct tcphdr *tcpheader = (struct tcphdr *)(data_li[i] +14 +ipheader->ihl*4);
            struct udphdr *udpheader = (struct udphdr *)(data_li[i] +14 +ipheader->ihl*4);
            qDebug() << "ipheader->protocol: " << ipheader->protocol;

            //由于接收双字节的网络序的，需要调整过来
            switch(ipheader->protocol){
                case ICMP:
                    icmpheader->checksum = htons(icmpheader->checksum);
                    icmpheader->un.echo.id = htons(icmpheader->un.echo.id);
                    icmpheader->un.echo.sequence = htons(icmpheader->un.echo.sequence);
                    break;
                case TCP:
                    tcpheader->source = htons(tcpheader->source);
                    tcpheader->dest = htons(tcpheader->dest);
                    tcpheader->window = htons(tcpheader->window);
                    tcpheader->check = htons(tcpheader->check);
                    tcpheader->seq = htonl(tcpheader->seq);
                    tcpheader->ack_seq = htonl(tcpheader->ack_seq);
                    break;
                case UDP:
                    udpheader->source = htons(udpheader->source);
                    udpheader->dest = htons(udpheader->dest);
                    udpheader->len = htons(udpheader->len);
                    udpheader->check = htons(udpheader->check);
            }

            i++;
            //超最大抓取数，清0
            if(i >= MAXDATAGRAM){
                i = 0;
                msg = "sniff..";
            }
            msg.append(".");
            //load_lb->setText(msg);
        } else {
            sleep(1);
        }
    }


    return;
}

void Sniff::run() {
    QString path ="";
    QString msg = "sniff...";
    int i = 0;

    state=START;

    /*Loop forever & call processPacket() for every received packet.*/
    //pcap_loop(device, -1, processPacket, (u_char *)&count);
    const unsigned char *p_packet_content = NULL; // 保存接收到的数据包的起始地址
    //pcap_t *pcap_handle = NULL;
    struct pcap_pkthdr protocol_header;
    while(state==START) {
        bzero(data_li[i], 4096);

        p_packet_content = pcap_next(device, &protocol_header);
        memcpy(data_li[i],p_packet_content,protocol_header.len);

        //p_packet_content  所捕获数据包的地址
        printf("Capture Time is :%s",ctime((const time_t *)&protocol_header.ts.tv_sec)); // 时间
        printf("Packet Lenght is :%d\n",protocol_header.len);	// 数据包的实际长度

        // 分析以太网中的 源mac、目的mac
        struct ethhdr *macheader = NULL;
        unsigned char *p_mac_string = NULL;			// 保存mac的地址，临时变量

        macheader = (struct ethhdr *)p_packet_content;  //struct ether_header 以太网帧头部
        ipheader = (struct iphdr *)(p_packet_content + 14);

        //只抓IP 数据包
        if(macheader->h_proto != 8)
            continue;

        //过滤器
        if(ipheader->protocol != filter && filter != ALL)
            continue;

        p_mac_string = (unsigned char *)macheader->h_source;//获取源mac
        printf("Mac Source Address is %02x:%02x:%02x:%02x:%02x:%02x\n",*(p_mac_string+0),*(p_mac_string+1),*(p_mac_string+2),*(p_mac_string+3),*(p_mac_string+4),*(p_mac_string+5));

        p_mac_string = (unsigned char *)macheader->h_dest;//获取目的mac
        printf("Mac Destination Address is %02x:%02x:%02x:%02x:%02x:%02x\n",*(p_mac_string+0),*(p_mac_string+1),*(p_mac_string+2),*(p_mac_string+3),*(p_mac_string+4),*(p_mac_string+5));

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

        path.append(QString("%1:%2.%3.%4.%5->").arg(getProtocol(ipheader->protocol))
                    .arg(QString::number((uint8_t)saddr[0]))
                    .arg(QString::number((uint8_t)saddr[1]))
                    .arg(QString::number((uint8_t)saddr[2]))
                    .arg(QString::number((uint8_t)saddr[3])));
        path.append(QString("%1.%2.%3.%4").arg(QString::number((uint8_t)daddr[0]))
                    .arg(QString::number((uint8_t)daddr[1]))
                    .arg(QString::number((uint8_t)daddr[2]))
                    .arg(QString::number((uint8_t)daddr[3])));
        qDebug() << path;


        //获当前时间
        QDateTime current_date_time = QDateTime::currentDateTime();
        QString current_date = current_date_time.toString(" hh:mm:ss yyyy-MM-dd");
        qDebug() << current_date;

        //显示数据包类型+抓取时间
        path.append(QString("\t  (%1)").arg(current_date));
        qDebug() << path;
        //显示
        if(i == 0)
            list_lw->clear();

        list_lw->addItem(path);
        path.clear();

        ///由于接收双字节的顺序网络序的，需要调整过来
        //ipheader->tot_len = (ipheader->tot_len>>8) + (ipheader->tot_len<<8);
        //ipheader->id = (ipheader->id>>8) + (ipheader->id<<8);
        //ipheader->frag_off = (ipheader->frag_off>>8) + (ipheader->frag_off<<8);
        //ipheader->check = (ipheader->check>>8) + (ipheader->check<<8);
        ipheader->tot_len = htons(ipheader->tot_len);
        ipheader->id = htons(ipheader->id);
        ipheader->frag_off = htons(ipheader->frag_off);
        ipheader->check = htons(ipheader->check);

        struct icmphdr *icmpheader = (struct icmphdr *)(p_packet_content +14 +ipheader->ihl*4);
        struct tcphdr *tcpheader = (struct tcphdr *)(p_packet_content +14 +ipheader->ihl*4);
        struct udphdr *udpheader = (struct udphdr *)(p_packet_content +14 +ipheader->ihl*4);
        qDebug() << "ipheader->protocol: " << ipheader->protocol;

        //由于接收双字节的网络序的，需要调整过来
        switch(ipheader->protocol){
            case ICMP:
                icmpheader->checksum = htons(icmpheader->checksum);
                icmpheader->un.echo.id = htons(icmpheader->un.echo.id);
                icmpheader->un.echo.sequence = htons(icmpheader->un.echo.sequence);
                break;
            case TCP:
                tcpheader->source = htons(tcpheader->source);
                tcpheader->dest = htons(tcpheader->dest);
                tcpheader->window = htons(tcpheader->window);
                tcpheader->check = htons(tcpheader->check);
                tcpheader->seq = htonl(tcpheader->seq);
                tcpheader->ack_seq = htonl(tcpheader->ack_seq);
                break;
            case UDP:
                udpheader->source = htons(udpheader->source);
                udpheader->dest = htons(udpheader->dest);
                udpheader->len = htons(udpheader->len);
                udpheader->check = htons(udpheader->check);
        }

        i++;
        //超最大抓取数，清0
        if(i >= MAXDATAGRAM){
            i = 0;
            msg = "sniff..";
            char a;
            scanf("%c",&a);
        }
        msg.append(".");
        load_lb->setText(msg);
    }

}

//把类型转成字符串
QString Sniff::getProtocol(int protocol) {
    switch(protocol) {
        case ICMP:
            return "ICMP";
            break;
        case TCP:
            return "TCP";
            break;
        case UDP:
            return "UDP";
    }
    return "UNKNOWN";
}

//设置显示控件
void Sniff::setW(QListWidget *_list_lw, QLabel *_load_lb) {
    list_lw = _list_lw;
    load_lb = _load_lb;
}

//允许抓取
void Sniff::startsniff(int _filter) {
    setFilter(_filter);
    state = START;
    load_lb->setText("sniff...");
}

//停止抓取
void Sniff::stop() {
    state = END;
    pcap_close(device);
    qDebug()<<"end";
    load_lb->setText("Stop!");
}

//设置过滤器
void Sniff::setFilter(int _filter) {
    filter = _filter;
}
