#include "mainwindow.h"
#include "ui_mainwindow.h"
#include "Sniffer.h"
#include "dialoginterface.h"

MainWindow::MainWindow(QWidget *parent) :
    QMainWindow(parent),
    ui(new Ui::MainWindow)
{
    ui->setupUi(this);
    ui->pb_scroll->setCheckable(true);
    ui->tableWidget->setSelectionBehavior(QAbstractItemView::SelectRows);

    thread = new QThread();
    sniffer = new Sniffer();
    sniffer->moveToThread(thread);

    QTimer *timer = new QTimer(this);
    timer->setInterval(100);
    timer->start(100);
    connect(thread, SIGNAL(started()), sniffer, SLOT(Start()));
    connect(timer, SIGNAL(timeout()), this, SLOT(getNewPackets()));

    connect(ui->pb_sniff, SIGNAL(clicked()), this, SLOT(ToggleSniffer()));
    connect(ui->pb_clear, SIGNAL(clicked()), this, SLOT(Clear()));
}

MainWindow::~MainWindow()
{
    delete ui;
}

void    MainWindow::Clear()
{
    sniffer->mutex.lock();
    ui->tableWidget->clearContents();
    ui->tableWidget->setRowCount(0);
    for (std::list<SniffedPacket *>::iterator it = sniffer->Packets.begin(); it != sniffer->Packets.end(); it++)
        delete *it;
    sniffer->Packets.clear();
    sniffer->mutex.unlock();
}

void    MainWindow::getNewPackets()
{
    if (!this->sniffer->IsSniffing())
        return ;

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
    if (ui->pb_scroll->isChecked())
        ui->tableWidget->scrollToBottom();

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

void                MainWindow::StartSniffing(const std::string &interface)
{
    sniffer->Initialize(interface);
    thread->start();
    ui->pb_sniff->setText("STOP");
}

void                MainWindow::ToggleSniffer()
{
    if (this->sniffer->IsSniffing())
    {
        this->sniffer->Stop();
        if (!thread->wait(500))
        {
            thread->terminate();
            thread->wait();
        }
        this->sniffer->DeInitialize();
        ui->pb_sniff->setText("START");

        return ;
    }

    DialogInterface win(this);
    win.exec();
}
