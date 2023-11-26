/********************************************************************************
** Form generated from reading UI file 'mainwindow.ui'
**
** Created by: Qt User Interface Compiler version 5.12.8
**
** WARNING! All changes made in this file will be lost when recompiling UI file!
********************************************************************************/

#ifndef UI_MAINWINDOW_H
#define UI_MAINWINDOW_H

#include <QtCore/QVariant>
#include <QtWidgets/QApplication>
#include <QtWidgets/QLabel>
#include <QtWidgets/QListWidget>
#include <QtWidgets/QMainWindow>
#include <QtWidgets/QMenuBar>
#include <QtWidgets/QPushButton>
#include <QtWidgets/QStatusBar>
#include <QtWidgets/QWidget>

QT_BEGIN_NAMESPACE

class Ui_MainWindow
{
public:
    QWidget *centralwidget;
    QPushButton *start;
    QPushButton *end;
    QPushButton *clear;
    QListWidget *linkShow;
    QListWidget *pkgShow;
    QLabel *label_load;
    QMenuBar *menubar;
    QStatusBar *statusbar;

    void setupUi(QMainWindow *MainWindow)
    {
        if (MainWindow->objectName().isEmpty())
            MainWindow->setObjectName(QString::fromUtf8("MainWindow"));
        MainWindow->resize(800, 600);
        centralwidget = new QWidget(MainWindow);
        centralwidget->setObjectName(QString::fromUtf8("centralwidget"));
        start = new QPushButton(centralwidget);
        start->setObjectName(QString::fromUtf8("start"));
        start->setGeometry(QRect(30, 20, 89, 41));
        end = new QPushButton(centralwidget);
        end->setObjectName(QString::fromUtf8("end"));
        end->setGeometry(QRect(30, 80, 89, 41));
        clear = new QPushButton(centralwidget);
        clear->setObjectName(QString::fromUtf8("clear"));
        clear->setGeometry(QRect(30, 134, 89, 41));
        linkShow = new QListWidget(centralwidget);
        linkShow->setObjectName(QString::fromUtf8("linkShow"));
        linkShow->setGeometry(QRect(20, 210, 761, 341));
        pkgShow = new QListWidget(centralwidget);
        pkgShow->setObjectName(QString::fromUtf8("pkgShow"));
        pkgShow->setGeometry(QRect(140, 20, 631, 151));
        label_load = new QLabel(centralwidget);
        label_load->setObjectName(QString::fromUtf8("label_load"));
        label_load->setEnabled(false);
        label_load->setGeometry(QRect(30, 170, 141, 41));
        MainWindow->setCentralWidget(centralwidget);
        menubar = new QMenuBar(MainWindow);
        menubar->setObjectName(QString::fromUtf8("menubar"));
        menubar->setGeometry(QRect(0, 0, 800, 22));
        MainWindow->setMenuBar(menubar);
        statusbar = new QStatusBar(MainWindow);
        statusbar->setObjectName(QString::fromUtf8("statusbar"));
        MainWindow->setStatusBar(statusbar);

        retranslateUi(MainWindow);

        QMetaObject::connectSlotsByName(MainWindow);
    } // setupUi

    void retranslateUi(QMainWindow *MainWindow)
    {
        MainWindow->setWindowTitle(QApplication::translate("MainWindow", "MainWindow", nullptr));
        start->setText(QApplication::translate("MainWindow", "Start", nullptr));
        end->setText(QApplication::translate("MainWindow", "End", nullptr));
        clear->setText(QApplication::translate("MainWindow", "Clear", nullptr));
        label_load->setText(QApplication::translate("MainWindow", "loading...", nullptr));
    } // retranslateUi

};

namespace Ui {
    class MainWindow: public Ui_MainWindow {};
} // namespace Ui

QT_END_NAMESPACE

#endif // UI_MAINWINDOW_H
