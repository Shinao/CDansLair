#include "Sniffer.h"

IP_HDR                      *Sniffer::iphdr;
TCP_HDR                     *Sniffer::tcphdr;
ICMP_HDR                    *Sniffer::icmphdr;
UDP_HDR                     *Sniffer::udphdr;
std::map<int, std::string>  Sniffer::ProtocolInfo;
std::list<SniffedPacket *>  Sniffer::Packets;
QMutex                      Sniffer::mutex;

Sniffer::Sniffer()
{
    this->Initialized = false;
    this->Sniffing = false;
    this->InterfaceStatus = 0;

    ProtocolInfo[ICMP] = "ICMP";
    ProtocolInfo[TCP] = "TCP";
    ProtocolInfo[UDP] = "UDP";
    ProtocolInfo[2] = "IGMP";
    ProtocolInfo[128] = "SSCOPMCE";
    ProtocolInfo[119] = "SRP";
    ProtocolInfo[31] = "MFENSP";
    ProtocolInfo[16] = "CHAOS";
    ProtocolInfo[0] = "HOPOPT";
    ProtocolInfo[22] = "XNSIDP";
    ProtocolInfo[111] = "IPXinIP";
    ProtocolInfo[103] = "PIM";
}

Sniffer::~Sniffer()
{
    this->DeInitialize();
}

void Sniffer::Start()
{
    this->Sniffing = true;
    this->Sniff();
}

void Sniffer::Stop()
{
    this->Sniffing = false;
}

bool    Sniffer::ManageError(const std::string &msg)
{
    qDebug() << "Error : " << msg.c_str();

#ifdef _WIN32
    qDebug() << "Windows Error ID : " << WSAGetLastError();
#endif

    return (false);
}

bool Sniffer::IsSniffing()
{
    return this->Sniffing;
}

void Sniffer::DeInitialize()
{
    if (!this->Initialized || this->Sniffing)
        return;

    this->Initialized = false;

#ifdef __linux__
    close(this->SniffSocket);
#elif _WIN32
    closesocket(this->SniffSocket);
    WSACleanup();
#endif

    this->Initialized = false;
}

bool Sniffer::Initialize(const std::string &interface)
{
    if (this->Initialized)
        return false;

    this->Interface = interface;

#ifdef _WIN32
    WSADATA WSA;
    if (WSAStartup(MAKEWORD(2, 2), &WSA) != 0)
        return (ManageError("Initialize socket"));
    this->SniffSocket = socket(AF_INET, SOCK_RAW, IPPROTO_IP);
#elif __linux__
    this->SniffSocket = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
#endif

    if (this->SniffSocket == INVALID_SOCKET)
        return (ManageError("Invalid socket"));

    // TO REMOVE
    char HostName[64];
    if (gethostname(HostName, sizeof(HostName)) == SOCKET_ERROR)
        return (ManageError("Get host name error"));
    struct hostent *LocalHost;
    LocalHost = gethostbyname(HostName);
    if (LocalHost == nullptr)
        return (ManageError("Localhost gethostbyname"));

#ifdef __linux__
    struct sockaddr_ll sll;
    struct ifreq ifr;

    memset(&sll, 0, sizeof(sll));
    memset(&ifr, 0, sizeof(ifr));

    strcpy(ifr.ifr_name, interface.c_str());

    if((ioctl( this->SniffSocket, SIOCGIFINDEX, &ifr)) == -1)
        return (ManageError("Set interface socket"));
    sll.sll_family = AF_PACKET;
    sll.sll_ifindex = ifr.ifr_ifindex;
    sll.sll_protocol = htons(ETH_P_ALL);

    if (bind( this->SniffSocket, (struct sockaddr*)&sll, sizeof( sll)) == -1)
      return (ManageError("Bind socket"));

 #elif _WIN32
    memset(&this->Destination, 0, sizeof(this->Destination));
    this->Destination.sin_addr.s_addr = inet_addr(this->Interface.c_str());
    this->Destination.sin_family = AF_INET;
    this->Destination.sin_port = 0;

    if (bind(this->SniffSocket, reinterpret_cast<SOCKADDR*>(&this->Destination), sizeof(this->Destination)) == SOCKET_ERROR)
        return (ManageError("Bind socket"));

    int Buff = 1;
    if (WSAIoctl(this->SniffSocket, _WSAIOW(IOC_VENDOR, 1), &Buff, sizeof(Buff), 0, 0, reinterpret_cast<LPDWORD>(&this->InterfaceStatus), 0,0) == SOCKET_ERROR)
        return (ManageError("Setting interface socket"));
#endif

    // Timeout recvfrom
    struct timeval tv;
    tv.tv_sec = 1;
    tv.tv_usec = 0;
    setsockopt(this->SniffSocket, SOL_SOCKET, SO_RCVTIMEO, (char *) &tv, sizeof(struct timeval));

    this->data = new char[1024 * 1024];
    memset(data, 0, 1024 * 1024);

    this->Initialized = true;
    return true;
}

void Sniffer::Sniff()
{
    while (this->Sniffing)
    {
        this->data_size = recvfrom(this->SniffSocket, this->data, 1024 * 1024, 0, 0, 0);
        this->ManagePacket(this->data, this->data_size);
    }
}

void Sniffer::ManagePacket(char *data, int data_size, bool pcap)
{
    if (data_size <= 0 || data_size > 65000)
        return;

    SniffedPacket *p = new SniffedPacket();
    p->has_ether_hdr = false;
    char    *pdata = new char[data_size + 1];
    std::memcpy(pdata, data, data_size);

    if (pcap)
        p->has_ether_hdr = true;

#ifdef __linux__
    p->has_ether_hdr = true;
#endif

    if (!p->has_ether_hdr)
        Sniffer::iphdr = (IP_HDR *) pdata;
    else
        Sniffer::iphdr = (IP_HDR *) (pdata + ETHER_HDR_SIZE);

    // Set data packet
    p->ip_source = inet_ntoa(*((in_addr *) &Sniffer::iphdr->ip_srcaddr));
    p->ip_dest = inet_ntoa(*((in_addr *) &Sniffer::iphdr->ip_destaddr));
    p->size = data_size;
    p->data = pdata;

    p->iphdr_size = Sniffer::iphdr->ip_header_len * 4;

    if (p->has_ether_hdr && p->ip_source == "0.0.0.0")
    {
        QByteArray array = QByteArray(data, 6);
        p->ip_source = QString(array.toHex()).toStdString();
    }
    if (p->has_ether_hdr && p->ip_dest == "0.0.0.0")
    {
        QByteArray array = QByteArray(data + 6, 6);
        p->ip_dest = QString(array.toHex()).toStdString();
    }

    int protocol = Sniffer::iphdr->ip_protocol;
    if (ProtocolInfo.find(protocol) != ProtocolInfo.end())
        p->protocol = ProtocolInfo[protocol].c_str();
    else
        p->protocol = QString::number(protocol);

    // Specific info packet
    if (protocol == ICMP)
        Sniffer::ICMPPacket(*p);
    else if (protocol == TCP)
        Sniffer::TCPPacket(*p);
    else if (protocol == UDP)
        Sniffer::UDPPacket(*p);

    // Transmitting packet
    mutex.lock();
    Packets.push_back(p);
    mutex.unlock();

}

const std::string &Sniffer::GetInterface()
{
    return this->Interface;
}

void Sniffer::TCPPacket(SniffedPacket &packet)
{
    Sniffer::tcphdr = (TCP_HDR *)((char *) Sniffer::iphdr + packet.iphdr_size);
    packet.protocol = "TCP";

    packet.sport = ntohs(Sniffer::tcphdr->source_port);
    packet.dport = ntohs(Sniffer::tcphdr->dest_port);
    packet.info = "Source port: " + QString::number(ntohs(Sniffer::tcphdr->source_port)) + "    Destination port: " + QString::number(ntohs(Sniffer::tcphdr->dest_port))
            + "   Acknowledge: " +  QString::number(ntohs(Sniffer::tcphdr->acknowledge)) + "     Checksum: " + QString::number(ntohs(Sniffer::tcphdr->checksum));


    /*
    std::fstream File("OutputLog.txt", std::ios::out | std::ios::app);

    if (File.is_open())
    {
        File << "\n";
        File << "TCP\n";
        File << (this->BuffSize - IPHDR_LENGTH)  << "\n";
        File << "IP Header Length : " << (unsigned int)this->iphdr->ip_header_len << "\n";
        File << "IP Total Length :  " << ntohs(this->iphdr->ip_total_length) << "\n";
        File << "Source IP :        " << inet_ntoa(this->Source.sin_addr) << "\n";
        File << "Destination IP :   " << inet_ntoa(this->Destination.sin_addr) << "\n";
        File << "Window :           " << ntohs(this->tcphdr->window) << "\n";
        File << "IP Header :        " << this->PrintBuffer(this->Buffer, IPHDR_LENGTH) << "\n";
        File << "TCP Header :       " << this->PrintBuffer(this->Buffer + IPHDR_LENGTH, this->tcphdr->data_offset * 4) << "\n";
        File << "Payload :          " << this->PrintBuffer(this->Buffer + IPHDR_LENGTH + this->tcphdr->data_offset * 4, this->BuffSize - tcphdr->data_offset * 4 - iphdr->ip_header_len * 4) << "\n";
        File << "Checksum :         " << ntohs(this->tcphdr->checksum) << "\n";
        File.close();
    }
*/
}

void Sniffer::ICMPPacket(SniffedPacket &packet)
{
    packet.protocol = "ICMP";

    unsigned short iphdr_size = Sniffer::iphdr->ip_header_len * 4;
    Sniffer::icmphdr = (ICMP_HDR *)((char *) Sniffer::iphdr + iphdr_size);

    if (Sniffer::icmphdr->type == 0 && Sniffer::icmphdr->code == 0)
        packet.info = "Echo (ping) reply";
    else if (Sniffer::icmphdr->type == 8 && Sniffer::icmphdr->code == 0)
        packet.info = "Echo (ping) request";
}

void Sniffer::UDPPacket(SniffedPacket &packet)
{
    packet.protocol = "UDP";

    unsigned short iphdr_size = Sniffer::iphdr->ip_header_len * 4;
    Sniffer::udphdr = (UDP_HDR *)((char *) Sniffer::iphdr + iphdr_size);

    packet.info = "Source port: " + QString::number(ntohs(Sniffer::udphdr->source_port)) + "    Destination port: " + QString::number(ntohs(Sniffer::udphdr->dest_port));
}
