#include "Sniffer.h"

Sniffer::Sniffer()
{
    this->Initialized = false;
    this->Sniffing = false;
    this->InterfaceStatus = 0;
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

    strcpy(ifr.ifr_name, "wlan0");

    if((ioctl( this->SniffSocket, SIOCGIFINDEX, &ifr)) == -1)
        return (ManageError("Set interface socket"));
    sll.sll_family = AF_PACKET;
    sll.sll_ifindex = ifr.ifr_ifindex;
    sll.sll_protocol = htons( ETH_P_ALL);

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

    // TO CHANGE
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
        if (this->data_size > 0)
            this->ManagePacket();
    }
}

void Sniffer::ManagePacket()
{
    this->iphdr = (IP_HDR *) this->data;

#ifdef __linux__
    this->iphdr = (IP_HDR *) (this->data + sizeof(struct ether_header));
#endif

    // Set data packet
    SniffedPacket *p = new SniffedPacket();
    p->ip_source = inet_ntoa(*((in_addr *) &this->iphdr->ip_srcaddr));
    p->ip_dest = inet_ntoa(*((in_addr *) &this->iphdr->ip_destaddr));
    p->size = this->data_size;

    // Specific info packet
    switch (this->iphdr->ip_protocol)
    {
        case ICMP:
            this->ICMPPacket(*p);
            break;
        case TCP:
            this->TCPPacket(*p);
            break;
        case UDP:
            this->UDPPacket(*p);
            break;
        default:
            p->protocol = QString::number(this->iphdr->ip_protocol);
            break;
    }

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
    packet.protocol = "TCP";

    unsigned short iphdr_size = this->iphdr->ip_header_len * 4;
    this->tcphdr = (TCP_HDR *)(this->data + iphdr_size);

    packet.info = QString::number(this->tcphdr->source_port) + " > " + QString::number(this->udphdr->dest_port);

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

    unsigned short iphdr_size = this->iphdr->ip_header_len * 4;
    this->icmphdr = (ICMP_HDR *)(this->data + iphdr_size);

    if (this->icmphdr->type == 0 && this->icmphdr->code == 0)
        packet.info = "Echo (ping) reply";
    else if (this->icmphdr->type == 8 && this->icmphdr->code == 0)
        packet.info = "Echo (ping) request";
}

void Sniffer::UDPPacket(SniffedPacket &packet)
{
    packet.protocol = "UDP";

    unsigned short iphdr_size = this->iphdr->ip_header_len * 4;
    this->udphdr = (UDP_HDR *)(this->data + iphdr_size);

    packet.info = "Source port: " + QString::number(this->udphdr->source_port) + "    Destination port: " + QString::number(this->udphdr->dest_port);
}

std::string Sniffer::PrintBuffer(char* data, int s)
{
    std::stringstream Val("");
    for (int I = 0; I < s; I++)
    {
        Val << data[I];
        Val << " ";
    }
    return Val.str();
}
