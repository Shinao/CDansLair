#include "mainwindow.h"
#include "ui_mainwindow.h"
#include "Sniffer.h"
#include "dialoginterface.h"
#include "dialogblock.h"
#include "dialogarp.h"
#include "dialogarp_options.h"
#include <QFileDialog>
#include <cstdlib>

MainWindow::MainWindow(QWidget *parent) :
    QMainWindow(parent),
    ui(new Ui::MainWindow)
{
    ui->setupUi(this);
    ui->pb_scroll->setCheckable(true);
    ui->pb_arp->setCheckable(true);
    ui->pb_arp->setEnabled(false);
    ui->tableWidget->setSelectionBehavior(QAbstractItemView::SelectRows);
    counter = 0;

    thread = new QThread();
    sniffer = new Sniffer();
    sniffer->moveToThread(thread);

    QTimer *timer = new QTimer(this);
    timer->setInterval(1);
    timer->start(100);
    connect(thread, SIGNAL(started()), sniffer, SLOT(Start()));
    connect(timer, SIGNAL(timeout()), this, SLOT(getNewPackets()));

    connect(ui->pb_sniff, SIGNAL(clicked()), this, SLOT(ToggleSniffer()));
    connect(ui->pb_clear, SIGNAL(clicked()), this, SLOT(Clear()));
    connect(ui->pb_load, SIGNAL(clicked()), this, SLOT(Load()));
    connect(ui->pb_save, SIGNAL(clicked()), this, SLOT(Save()));

    ui->pb_arp->setCheckable(true);
    ui->pb_block->setEnabled(false);

    // Linux specific : ARP mostly
//#ifdef __linux__
    connect(ui->pb_arp, SIGNAL(clicked()), this, SLOT(ArpPoisoning()));
    connect(ui->pb_block, SIGNAL(clicked()), this, SLOT(BlockIp()));
    connect(ui->pb_arp_options, SIGNAL(clicked()), this, SLOT(ArpOptions()));

    ui->pb_block->setEnabled(true);
    _arp_spoofer.Initialize();
//#endif
}

MainWindow::~MainWindow()
{
    delete ui;

#ifdef __linux__
    for (std::list<std::string>::iterator it = this->_blocked_ip.begin(); it != this->_blocked_ip.end(); it++)
    {
        char    str_cmd[100];
        str_cmd[0] = 0;
        strcat(str_cmd, "iptables -D INPUT -s ");
        strcat(str_cmd, (*it).c_str());
        strcat(str_cmd, " -j DROP");
        system(str_cmd);
    }
#endif
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
    if (counter++ == 20) // I don't have time for a proper way
    {
        counter = 0;
        _arp_spoofer.SendArpRedirectRequest();
    }

    sniffer->mutex.lock();

    for (std::list<SniffedPacket *>::iterator it = sniffer->Packets.begin(); it != sniffer->Packets.end(); it++)
    {
        //if (ui->pb_redirect->isChecked())
        _arp_spoofer.ManageNewPacket(*(*it));
        insertPacket(*(*it));
    }

    sniffer->Packets.clear();
    if (ui->pb_scroll->isChecked())
        ui->tableWidget->scrollToBottom();

    sniffer->mutex.unlock();
}

void    MainWindow::ArpOptionsSet()
{

}

void    MainWindow::insertPacket(SniffedPacket &packet)
{
    if (packet.protocol != "TCP")
        return;

    int i = ui->tableWidget->rowCount();
    ui->tableWidget->insertRow(i);

    insertToIndex(packet.protocol, packet.ip_source.c_str(), i, 0);
    insertToIndex(packet.protocol, packet.ip_dest.c_str(), i, 1);
    insertToIndex(packet.protocol, QString::number(packet.size), i, 2);
    insertToIndex(packet.protocol, packet.protocol, i, 3);
    insertToIndex(packet.protocol, packet.info, i, 4);

    this->Packets.push_back(&packet);
}

void    MainWindow::insertToIndex(const QString &protocol, const QString &str, int row, int col)
{
    QTableWidgetItem *item = new QTableWidgetItem(str);
    
        if (protocol == "TCP")
        item->setBackgroundColor(QColor(0, 0, 255, 100));
    if (protocol == "UDP")
    item->setBackgroundColor(QColor(255, 0, 0, 100));
    if (protocol == "ICMP")
        item->setBackgroundColor(QColor(255, 255, 0, 100));
        
    item->setFlags(Qt::ItemIsSelectable | Qt::ItemIsEnabled);
    if (col != 4)
        item->setTextAlignment(Qt::AlignCenter);
    ui->tableWidget->setItem(row, col, item);
}

void                MainWindow::StartSniffing(const std::string &interface)
{
    this->interface = interface;
    sniffer->Initialize(interface);
    thread->start();
    ui->pb_sniff->setText("STOP");

//#ifdef __linux__
    ui->pb_arp->setEnabled(true);
//#endif
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
        if (ui->pb_arp->isChecked())
        {
            _arp_spoofer.Stop();
            ui->pb_arp->setChecked(false);
        }
        ui->pb_arp->setEnabled(false);

        return ;
    }

    DialogInterface win(this, _local_ip, _local_mac);
    win.exec();
}

void                  MainWindow::ArpOptions()
{
    Dialogarp_options win(this);
    win.exec();
}

void                  MainWindow::Save()
{
    if (this->sniffer->IsSniffing())
        ToggleSniffer();

    QString           fileName = QFileDialog::getSaveFileName(this, tr("Save File"), "", tr("PCAP (*.pcap)"));

    std::ofstream file(fileName.toStdString(), std::ios::binary | std::ios::trunc | std::ios::out);
    if (file.is_open())
    {
        pcap_hdr_t	hdr;
        std::memset((char *) &hdr, 0, sizeof(hdr));
        hdr.magic_number = 0xA1B2C3D4;
        hdr.version_major = 2;
        hdr.version_minor = 4;
        hdr.snaplen = 65535;
        hdr.network = 1;
        file.write((char *) &hdr, sizeof(hdr));

        pcaprec_hdr_t hdrp;
        std::memset(&hdrp, 0, sizeof(hdrp));
        eth_hdr_t eth_hdr;
        eth_hdr.ether_type = 8;
        for (std::list<SniffedPacket *>::iterator it = this->Packets.begin(); it != this->Packets.end(); it++)
        {
            hdrp.incl_len = (*it)->size;
            if (!(*it)->has_ether_hdr)
                hdrp.incl_len += ETHER_HDR_SIZE;
            hdrp.orig_len = hdrp.incl_len;

            file.write((char *) &hdrp, sizeof(hdrp));
            if (!(*it)->has_ether_hdr)
                file.write((char *) &eth_hdr, ETHER_HDR_SIZE);
            file.write((*it)->data, (*it)->size);
        }

        file.close();
    }
    else
        qDebug() << "Unable to open file";
}

void                MainWindow::BlockIp()
{
    DialogBlock win(this);
    win.exec();
}

void                MainWindow::Block(const std::string &ip)
{
#ifdef __linux__
    if (ip.length() > 20)
        return;

    _blocked_ip.push_back(ip);

    char    str_cmd[100];
        str_cmd[0] = 0;
    strcat(str_cmd, "iptables -A INPUT -s ");
    strcat(str_cmd, ip.c_str());
    strcat(str_cmd, " -j DROP");
    system(str_cmd);
#endif
}

void    MainWindow::Unblock(const std::string &ip)
{
#ifdef __linux__
    if (ip.length() > 20)
        return;

    _blocked_ip.remove(ip);

    char    str_cmd[100];
    str_cmd[0] = 0;
    strcat(str_cmd, "iptables -D INPUT -s ");
    strcat(str_cmd, ip.c_str());
    strcat(str_cmd, " -j DROP");
    system(str_cmd);
#endif
}

void                  MainWindow::Load()
{
  if (this->sniffer->IsSniffing())
      ToggleSniffer();

  Clear();

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

    if (size < (int) sizeof(pcap_hdr_t))
        return ;

    pcap_hdr_t	&hdr = *(pcap_hdr_t *) memblock;
    if (hdr.magic_number != 0xa1b2c3d4)
    {
        qDebug() << "Wrong format";
        return ;
    }

    char *cursor = memblock + sizeof(hdr);
    pcaprec_hdr_t *hdrp;

    if (size < (int) sizeof(hdr) + (int) sizeof(hdrp))
        return;

    while ((int) (cursor - memblock) < size)
    {
      hdrp = (pcaprec_hdr_t *) cursor;

      cursor += sizeof(*hdrp);
      char  *data = cursor;

      if (size < cursor - memblock + hdrp->incl_len)
          return;

      Sniffer::ManagePacket(data, hdrp->incl_len, true);
      cursor += hdrp->incl_len;
    }

    delete[] memblock;
  }
  else
      qDebug() << "Unable to open file";
}

void                MainWindow::StartArp(const std::string &ip1, char *mac1, const std::string &ip2, char *mac2)
{
    _arp_spoofer.Start(_local_ip, _local_mac, ip1, mac1, ip2, mac2);
    ui->pb_arp->setChecked(true);
}

void                MainWindow::ArpPoisoning()
{
    if (ui->pb_arp->isChecked())
    {
        _arp_spoofer.Stop();
        ui->pb_arp->setChecked(false);

        return;
    }

    Dialogarp win(this);
    win.exec();
}
