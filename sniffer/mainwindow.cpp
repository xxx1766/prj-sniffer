#include "mainwindow.h"
#include "ui_mainwindow.h"
#include <QDebug>


MainWindow::MainWindow(QWidget *parent)
    : QMainWindow(parent)
    , ui(new Ui::MainWindow)
{
    ui->setupUi(this);

    // Sniff Start!
    mySniff = new Sniff();

    mySniff->setW(ui->linkShow, ui->label_load);
    //mySniff->start();

}

MainWindow::~MainWindow () {
    delete ui;
}

void MainWindow::on_start_clicked()
{

    int filter = ALL;

    //filter = check_filter(ui->comboBox_filter->currentText());
    mySniff->startsniff(filter);
    qDebug()<<"click Start!";
    mySniff->run();
}

void MainWindow::on_end_clicked()
{
    mySniff->stop();
    qDebug()<<"click End!";

}

void MainWindow::on_clear_clicked()
{
    qDebug()<<"click Clear!";
}

void MainWindow::on_linkShow_doubleClicked(const QModelIndex &index)
{
    int idx = index.row();
    qDebug()<<idx;
    char c_data[4096];
        char *p = c_data;
        ui->pkgShow->clear();
        p = mySniff->data_li[idx];
        showMac((struct ethhdr *) p);
        struct iphdr *ipheader = (struct iphdr *)(p + 14);
        showIP(ipheader);

        switch (ipheader->protocol) {
            case ICMP:
                showIcmp((struct icmphdr *)(p+14+ipheader->ihl*4));
                break;
            case TCP:
                showTcp((struct tcphdr *)(p+14+ipheader->ihl*4));
                break;
            case UDP:
                showUdp((struct udphdr *)(p+14+ipheader->ihl*4));
                break;
            default:
                break;
        }
}

//显示MAC首部
void MainWindow::showMac(ethhdr *mheader)
{
    QString temp;
    ui->pkgShow->addItem("****************** DLC HEADER **********************");
    temp.append(QString("源 MAC 地址: %1-%2-%3-%4-%5-%6")
                .arg(QString::number((int)(mheader->h_source[0]),16))
                .arg(QString::number((int)(mheader->h_source[1]),16))
                .arg(QString::number((int)(mheader->h_source[2]),16))
                .arg(QString::number((int)(mheader->h_source[3]),16))
                .arg(QString::number((int)(mheader->h_source[4]),16))
                .arg(QString::number((int)(mheader->h_source[5]),16)));
    ui->pkgShow->addItem(temp);
    temp.clear();
    temp.append(QString("目的MAC地址: %1-%2-%3-%4-%5-%6")
                .arg(QString::number((int)mheader->h_dest[0],16))
                .arg(QString::number((int)mheader->h_dest[1],16))
                .arg(QString::number((int)mheader->h_dest[2],16))
                .arg(QString::number((int)mheader->h_dest[3],16))
                .arg(QString::number((int)mheader->h_dest[4],16))
                .arg(QString::number((int)mheader->h_dest[5],16)));
    ui->pkgShow->addItem(temp);
    temp.clear();
    temp = "类型：";
    temp.append(QString::number((int)(mheader->h_proto)));
    ui->pkgShow->addItem(temp);
    temp.clear();
}

//显示IP首部
void MainWindow::showIP(struct iphdr *ipheader)
{
    QString temp;
    ui->pkgShow->addItem("****************** IP HEADER  **********************");

    temp.append(QString("版本号： %1")
                .arg(QString::number((ipheader->version))));
    ui->pkgShow->addItem(temp);
    temp.clear();
    temp.append(QString("首部长度： %1")
                .arg(QString::number((ipheader->ihl*4))));
    ui->pkgShow->addItem(temp);
    temp.clear();

    temp.append(QString("区分服务： %1")
                .arg(QString::number((ipheader->tos))));
    ui->pkgShow->addItem(temp);
    temp.clear();


    temp.append(QString("总长度： %1")
                .arg(QString::number((ipheader->tot_len))));
    ui->pkgShow->addItem(temp);
    temp.clear();

    temp.append(QString("标识: %1")
                .arg(QString::number((ipheader->id))));
    ui->pkgShow->addItem(temp);
    temp.clear();

    temp.append(QString("标志: %1")
                .arg(QString::number((ipheader->frag_off>>13))));
    ui->pkgShow->addItem(temp);
    temp.clear();

    temp.append(QString("片偏移:  %1")
                .arg(QString::number(( ipheader->frag_off&0x1fff))));
    ui->pkgShow->addItem(temp);
    temp.clear();

    temp.append(QString("生存时间: %1")
                .arg(QString::number(( ipheader->ttl))));
    ui->pkgShow->addItem(temp);
    temp.clear();

    temp.append(QString("协议:  %1")
                .arg(QString::number((ipheader->protocol))));
    ui->pkgShow->addItem(temp);
    temp.clear();

    temp.append(QString("检验和: %1")
                .arg(QString::number((ipheader->check))));
    ui->pkgShow->addItem(temp);
    temp.clear();

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

    temp.append(QString("源 IP: %1.%2.%3.%4")
                .arg(QString::number((uint8_t)saddr[0]))
                .arg(QString::number((uint8_t)saddr[1]))
                .arg(QString::number((uint8_t)saddr[2]))
                .arg(QString::number((uint8_t)saddr[3])));
    ui->pkgShow->addItem(temp);
    temp.clear();
    temp.append(QString("目的IP: %1.%2.%3.%4")
                .arg(QString::number((uint8_t)daddr[0]))
                .arg(QString::number((uint8_t)daddr[1]))
                .arg(QString::number((uint8_t)daddr[2]))
                .arg(QString::number((uint8_t)daddr[3])));
    ui->pkgShow->addItem(temp);
    temp.clear();
}
//显示ICMP首部
void MainWindow::showIcmp(icmphdr *icmpheader)
{
    QString temp;
    ui->pkgShow->addItem("****************** ICMP HEADER  **********************");
    temp.append(QString("类型： %1")
                .arg(QString::number((icmpheader->type))));
    ui->pkgShow->addItem(temp);
    temp.clear();
    temp.append(QString("代码： %1")
                .arg(QString::number((icmpheader->code))));
    ui->pkgShow->addItem(temp);
    temp.clear();
    temp.append(QString("检验和： %1")
                .arg(QString::number((icmpheader->checksum))));
    ui->pkgShow->addItem(temp);
    temp.clear();
    temp.append(QString("标识符： %1")
                .arg(QString::number((icmpheader->un.echo.id))));
    ui->pkgShow->addItem(temp);
    temp.clear();
    temp.append(QString("序列号： %1")
                .arg(QString::number((icmpheader->un.echo.sequence))));
    ui->pkgShow->addItem(temp);
    temp.clear();
}
//显示TCP首部
void MainWindow::showTcp(tcphdr *tcpheader)
{
    QString temp;
    ui->pkgShow->addItem("****************** TCP HEADER  **********************");
    temp.append(QString("源端口： %1")
                .arg(QString::number((tcpheader->source))));
    ui->pkgShow->addItem(temp);
    temp.clear();
    temp.append(QString("目的端口： %1")
                .arg(QString::number((tcpheader->dest))));
    ui->pkgShow->addItem(temp);
    temp.clear();
    temp.append(QString("序号： %1")
                .arg(QString::number((tcpheader->seq))));
    ui->pkgShow->addItem(temp);
    temp.clear();
    temp.append(QString("确认号： %1")
                .arg(QString::number((tcpheader->ack_seq))));
    ui->pkgShow->addItem(temp);
    temp.clear();
    temp.append(QString("数据偏移： %1")
                .arg(QString::number((tcpheader->doff*4))));
    ui->pkgShow->addItem(temp);
    temp.clear();
    temp.append(QString("标志位：  URG:%1 ACK:%2 PSH:%3 RST:%4 SYN:%5 FIN:%6")
                .arg(QString::number((int)(tcpheader->urg)))
                .arg(QString::number((int)(tcpheader->ack)))
                .arg(QString::number((int)(tcpheader->psh)))
                .arg(QString::number((int)(tcpheader->rst)))
                .arg(QString::number((int)(tcpheader->syn)))
                .arg(QString::number((int)(tcpheader->fin))));
    ui->pkgShow->addItem(temp);
    temp.clear();
    temp.append(QString("窗口： %1")
                .arg(QString::number((tcpheader->window))));
    ui->pkgShow->addItem(temp);
    temp.clear();
    temp.append(QString("检验和： %1")
                .arg(QString::number((tcpheader->check))));
    ui->pkgShow->addItem(temp);
    temp.clear();
}
//显示UDP首部
void MainWindow::showUdp(udphdr *udpheader)
{
    QString temp;
    ui->pkgShow->addItem("****************** UDP HEADER  **********************");
    temp.append(QString("源端口： %1")
                .arg(QString::number((udpheader->source))));
    ui->pkgShow->addItem(temp);
    temp.clear();
    temp.append(QString("目的端口： %1")
                .arg(QString::number((udpheader->dest))));
    ui->pkgShow->addItem(temp);
    temp.clear();
    temp.append(QString("长度： %1")
                .arg(QString::number((udpheader->len))));
    ui->pkgShow->addItem(temp);
    temp.clear();
    temp.append(QString("检验和： %1")
                .arg(QString::number((udpheader->check))));
    ui->pkgShow->addItem(temp);
    temp.clear();

}
