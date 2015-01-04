#include "mainwindow.h"
#include "ui_mainwindow.h"
#include "Sniffer.h"
#include "dialoginterface.h"
#include <QFileDialog>

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
    connect(ui->pb_load, SIGNAL(clicked()), this, SLOT(Load()));
    connect(ui->pb_save, SIGNAL(clicked()), this, SLOT(Save()));
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
    for (std::list<SniffedPacket *>::iterator it = this->Packets.begin(); it != this->Packets.end(); it++)
        delete *it;
    this->Packets.clear();
    sniffer->mutex.unlock();
}

void    MainWindow::getNewPackets()
{
    //if (!this->sniffer->IsSniffing())
      //  return ;

    sniffer->mutex.lock();

    for (std::list<SniffedPacket *>::iterator it = sniffer->Packets.begin(); it != sniffer->Packets.end(); it++)
        insertPacket(*(*it));

    sniffer->Packets.clear();
    if (ui->pb_scroll->isChecked())
        ui->tableWidget->scrollToBottom();

    sniffer->mutex.unlock();
}

void    MainWindow::insertPacket(SniffedPacket &packet)
{
    int i = ui->tableWidget->rowCount();
    ui->tableWidget->insertRow(i);

    insertToIndex(packet.ip_source.c_str(), i, 0);
    insertToIndex(packet.ip_dest.c_str(), i, 1);
    insertToIndex(QString::number(packet.size), i, 2);
    insertToIndex(packet.protocol, i, 3);
    insertToIndex(packet.info, i, 4);

    this->Packets.push_back(&packet);
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

void                  MainWindow::Save()
{

}

void                  MainWindow::Load()
{
  if (this->sniffer->IsSniffing())
      ToggleSniffer();

  QString           fileName = QFileDialog::getOpenFileName(this, tr("Load File"), "", tr("PCAP (*.pcap)"));
  std::streampos    size;
  char              *memblock;

  std::ifstream file(fileName.toStdString(), std::ios::in | std::ios::binary | std::ios::ate);
  if (file.is_open())
  {
    size = file.tellg();
    memblock = new char [size];
    file.seekg (0, std::ios::beg);
    file.read (memblock, size);
    file.close();

    pcap_hdr_t	&hdr = *(pcap_hdr_t *) memblock;
    if (hdr.magic_number != 0xd4c3b2a1 && hdr.magic_number != 0xa1b2c3d4 && hdr.magic_number != 0xa1b23c4d && hdr.magic_number != 0x4d3cb2a1)
    {
        qDebug () << "Wrong format";
        return ;
    }

    char *cursor = memblock + sizeof(pcap_hdr_t);
    pcaprec_hdr_t *hdrp;

    while ((int) (cursor - memblock) < size)
    {
      hdrp = (pcaprec_hdr_t *) cursor;

      cursor += sizeof(pcaprec_hdr_t);
      char  *data = cursor;

      Sniffer::ManagePacket(data, hdrp->incl_len, true);
      cursor += hdrp->incl_len;
    }

    delete[] memblock;
  }
  else
      qDebug() << "Unable to open file";
}
