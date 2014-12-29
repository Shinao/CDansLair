#include "mainwindow.h"
#include "ui_mainwindow.h"
#include "Sniffer.h"

MainWindow::MainWindow(QWidget *parent) :
    QMainWindow(parent),
    ui(new Ui::MainWindow)
{
    ui->setupUi(this);
    ui->tableWidget->setSelectionBehavior(QAbstractItemView::SelectRows);

    thread = new QThread();
    sniffer = new Sniffer();
    sniffer->moveToThread(thread);
    sniffer->SetInterface(0);
    sniffer->Initialize();

    QTimer *timer = new QTimer(this);
    timer->setInterval(100);
    timer->start(100);
    connect(thread, SIGNAL(started()), sniffer, SLOT(Start()));
    thread->start();
    connect(timer, SIGNAL(timeout()), this, SLOT(getNewPackets()));
}

MainWindow::~MainWindow()
{
    delete ui;
}

void    MainWindow::getNewPackets()
{
    sniffer->mutex.lock();

    for (std::list<SniffedPacket *>::iterator it = sniffer->Packets.begin(); it != sniffer->Packets.end(); it++)
    {
        int i = ui->tableWidget->rowCount();
        ui->tableWidget->insertRow(i);

        SniffedPacket &packet = *(*it);
        insertToIndex(packet.ip_source.c_str(), i, 0);
        insertToIndex(packet.ip_dest.c_str(), i, 1);
        insertToIndex(QString::number(packet.size), i, 2);
        insertToIndex(packet.protocol, i, 3);
        insertToIndex(packet.info, i, 4);
    }

    sniffer->Packets.clear();
    //ui->tableWidget->scrollToBottom();

    sniffer->mutex.unlock();
}

void    MainWindow::insertToIndex(const QString &str, int row, int col)
{
    QTableWidgetItem *item = new QTableWidgetItem(str);
    item->setFlags(Qt::ItemIsSelectable | Qt::ItemIsEnabled);
    if (col != 4)
        item->setTextAlignment(Qt::AlignCenter);
    ui->tableWidget->setItem(row, col, item);
}
