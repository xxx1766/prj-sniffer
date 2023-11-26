#ifndef MAINWINDOW_H
#define MAINWINDOW_H

#include <QMainWindow>
#include "sniff.h"

QT_BEGIN_NAMESPACE
namespace Ui { class MainWindow; }
QT_END_NAMESPACE

class MainWindow : public QMainWindow
{
    Q_OBJECT

public:
    MainWindow(QWidget *parent = nullptr);
    ~MainWindow();
    void showMac(struct ethhdr *mheader);
    void showIP(struct iphdr *ipheader);
    void showIcmp(icmphdr *icmpheader);
    void showTcp(struct tcphdr *tcpheader);
    void showUdp(struct udphdr *udpheader);
    int check_filter(QString qf);

private slots:
    void on_start_clicked();
    void on_end_clicked();
    void on_clear_clicked();
    void on_linkShow_doubleClicked(const QModelIndex &index);

private:
    Ui::MainWindow *ui;
    Sniff *mySniff;
};
#endif // MAINWINDOW_H
