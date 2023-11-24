#include "mainwindow.h"
#include "ui_mainwindow.h"
#include <QDebug>
Sniff *mySniff = new Sniff();

MainWindow::MainWindow(QWidget *parent)
    : QMainWindow(parent)
    , ui(new Ui::MainWindow)
{
    ui->setupUi(this);

    // Sniff Start!

    //mySniff->setW(ui->snifferCnt, ui->label);
    mySniff->start();

}

MainWindow::~MainWindow () {
    delete ui;
}

void MainWindow::on_start_clicked()
{
    qDebug()<<"click Start!";
    int filter = ALL;
    //filter = check_filter(ui->comboBox_filter->currentText());
    mySniff->startsniff(filter);
}

void MainWindow::on_end_clicked()
{
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
}
