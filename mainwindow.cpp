#include "mainwindow.h"
#include "ui_mainwindow.h"
#include "Sniffer.h"

MainWindow::MainWindow(QWidget *parent) :
    QMainWindow(parent),
    ui(new Ui::MainWindow)
{

    ui->setupUi(this);
    thread = new QThread();
    sniffer = new Sniffer();
    sniffer->moveToThread(thread);
    try
    {

      sniffer->SetInterface(0);
      sniffer->Initialize();
      //s.Start();

    }
    catch (std::exception &e)
    {
      std::cout<<"\nERROR: "<<e.what();
      sniffer->Stop();
      sniffer->DeInitialize();
    }

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
        QTableWidgetItem *item = new QTableWidgetItem((*it)->ip_source.c_str());
        item->setFlags(Qt::ItemIsSelectable | Qt::ItemIsEnabled);
        ui->tableWidget->setItem(i, 1, item);
        item = new QTableWidgetItem((*it)->ip_dest.c_str());
        item->setFlags(Qt::ItemIsSelectable | Qt::ItemIsEnabled);
        ui->tableWidget->setItem(i, 2, item);
    }

    sniffer->Packets.clear();

    ui->tableWidget->scrollToBottom();


    sniffer->mutex.unlock();
}
