#include "mainwindow.h"
#include "ui_mainwindow.h"
#include <QDebug>

MainWindow::MainWindow(QWidget *parent)
    : QMainWindow(parent)
    , ui(new Ui::MainWindow)
{
    ui->setupUi(this);
}

MainWindow::~MainWindow () {
    delete ui;
}

void MainWindow::on_start_clicked()
{
    qDebug()<<"click Start!";
}

void MainWindow::on_end_clicked()
{
    qDebug()<<"click End!";
}

void MainWindow::on_clear_clicked()
{
    qDebug()<<"click Clear!";
}
