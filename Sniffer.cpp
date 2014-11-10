#include "Sniffer.h"


std::string ErrorMessage(std::uint32_t Error, bool Throw)
{
    LPTSTR lpMsgBuf = nullptr;
    FormatMessage(FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS, nullptr, Error, MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT), reinterpret_cast<LPTSTR>(&lpMsgBuf), 0, nullptr);
    LogError;
    if (Throw)
    {
        //throw std::runtime_error(lpMsgBuf);
    }
    return ("");
    //return lpMsgBuf;
}

Sniffer::Sniffer()
{
    this->Initialized = false;
    this->Sniffing = false;
    this->Filter = false;
    this->SniffSource = false;
    this->SniffDestination = false;
    this->Interface = 0;
}

/*void Sniffer::Test()
{
}*/

Sniffer::~Sniffer()
{
    this->DeInitialize();
}

bool Sniffer::StringArrayContains(std::vector<std::string> Array, std::string Element)
{
    for (unsigned int I = 0; I < Array.size(); I++)
    {
        if (Array.at(I) == Element)
        {
            return true;
        }
    }
    return false;
}

void Sniffer::RemoveSourceIP(std::string OldIP)
{
    if (!this->StringArrayContains(this->SourceIP, OldIP))
        return;
    this->SourceIP.erase(std::remove(this->SourceIP.begin(), this->SourceIP.end(), OldIP), this->SourceIP.end());
}

void Sniffer::RemoveDestinationIP(std::string OldIP)
{
    if (!this->StringArrayContains(this->DestinationIP, OldIP))
        return;
    this->DestinationIP.erase(std::remove(this->DestinationIP.begin(), this->DestinationIP.end(), OldIP), this->DestinationIP.end());
}

void Sniffer::AddSourceIP(std::string NewIP)
{
    if (this->StringArrayContains(this->SourceIP, NewIP))
        return;
    this->SourceIP.push_back(NewIP);
}

void Sniffer::AddDestinationIP(std::string NewIP)
{
    if (this->StringArrayContains(this->DestinationIP, NewIP))
        return;
    this->DestinationIP.push_back(NewIP);
}

void Sniffer::Error()
{
    this->DeInitialize();
    ErrorMessage(WSAGetLastError(), true);
}

void Sniffer::DeInitialize()
{
    if (!this->Initialized)
        return;
    this->Sniffing = false;
    this->Stop();
    delete[] this->Buffer;
    this->SourceIP.clear();
    this->DestinationIP.clear();
    this->Interface = -1;
    this->BuffSize = -1;
    this->Filter = false;
    this->SniffSource = false;
    this->SniffDestination = false;
    this->iphdr = nullptr;
    this->tcphdr = nullptr;
    this->icmphdr = nullptr;
    this->udphdr = nullptr;
    closesocket(this->SniffSocket);
    WSACleanup();
    this->Initialized = false;
}

bool Sniffer::Initialize()
{
    if (this->Initialized)
        return true;
    WSADATA WSA;
    if (WSAStartup(MAKEWORD(2, 2), &WSA) != 0)
    {
        this->Error();
        return false;
    }
    this->SniffSocket = socket(AF_INET, SOCK_RAW, IPPROTO_IP);
    if (this->SniffSocket == INVALID_SOCKET)
    {
        this->Error();
        return false;
    }
    char HostName[64];
    if (gethostname(HostName, sizeof(HostName)) == SOCKET_ERROR)
    {
        this->Error();
        return false;
    }
    struct hostent *LocalHost;
    LocalHost = gethostbyname(HostName);
    if (LocalHost == nullptr)
    {
        this->Error();
        return false;
    }
    memset(&this->Destination, 0, sizeof(this->Destination));
    memcpy(&this->Destination.sin_addr.s_addr, LocalHost->h_addr_list[this->Interface], sizeof(this->Destination.sin_addr.s_addr));
    this->Destination.sin_family = AF_INET;
    this->Destination.sin_port = 0;
    if (bind(this->SniffSocket, reinterpret_cast<SOCKADDR*>(&this->Destination), sizeof(this->Destination)) == SOCKET_ERROR)
    {
        this->Error();
        return false;
    }
    int Buff = 1;
    if (WSAIoctl(this->SniffSocket, _WSAIOW(IOC_VENDOR, 1), &Buff, sizeof(Buff), 0, 0, reinterpret_cast<LPDWORD>(&this->Interface), 0,0) == SOCKET_ERROR)
    {
        this->Error();
        return false;
    }
    this->Buffer = new char[1024 * 1024];
    memset(Buffer, 0, 1024 * 1024);
    this->Initialized = true;
    return true;
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

void Sniffer::Sniff()
{
    while (this->Sniffing)
    {
        this->BuffSize = recvfrom(this->SniffSocket, this->Buffer, 1024 * 1024, 0, 0, 0);
        if (this->BuffSize > 0)
            this->Packet();
    }
}

std::string Sniffer::GetIP(std::string Address)
{
    if (!this->Initialized)
        return std::string();
    hostent* ResIP = gethostbyname(Address.c_str());
    if (ResIP == nullptr)
        return std::string();
    IN_ADDR addr;
    memcpy(&addr.S_un.S_addr, ResIP->h_addr, ResIP->h_length);
    return inet_ntoa(addr);
}

void Sniffer::SetInterface(int Interf)
{
    this->Interface = Interf;
}

int Sniffer::GetInterface()
{
    return this->Interface;
}

void Sniffer::HandleTCP()
{
    unsigned short IPHDR_LENGTH = this->iphdr->ip_header_len * 4;
    this->tcphdr = (TCP_HDR*)(this->Buffer + IPHDR_LENGTH);
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

void Sniffer::HandleICMP()
{
    unsigned short IPHDR_LENGTH = this->iphdr->ip_header_len * 4;
    this->icmphdr = (ICMP_HDR*)(this->Buffer + IPHDR_LENGTH);
}

void Sniffer::HandleUDP()
{
    unsigned short IPHDR_LENGTH = this->iphdr->ip_header_len * 4;
    this->udphdr = (UDP_HDR*)(this->Buffer + IPHDR_LENGTH);
}

void Sniffer::FilterIP(bool FilterIPs)
{
    this->Filter = FilterIPs;
}

void Sniffer::ListenSource(bool Listen)
{
    this->SniffSource = Listen;
}

void Sniffer::ListenDestination(bool Listen)
{
    this->SniffDestination = Listen;
}

void Sniffer::Packet()
{
    this->iphdr = (IPV4_HDR*)this->Buffer;
    memset(&this->Source, 0, sizeof(this->Source));
    this->Source.sin_addr.s_addr = this->iphdr->ip_srcaddr;
    memset(&this->Destination, 0, sizeof(this->Destination));
    this->Destination.sin_addr.s_addr = this->iphdr->ip_destaddr;
    if (this->Filter)
    {
        if (!(this->SniffSource && this->SniffDestination))
        {
            if (this->SniffSource && !this->StringArrayContains(this->SourceIP, inet_ntoa(this->Source.sin_addr)))
                return;
            if (this->SniffDestination && !this->StringArrayContains(this->DestinationIP, inet_ntoa(this->Destination.sin_addr)))
                return;
        } else
        {
            if (!(this->StringArrayContains(this->SourceIP, inet_ntoa(this->Source.sin_addr))) &&
                !(this->StringArrayContains(this->DestinationIP, inet_ntoa(this->Destination.sin_addr))))
                    return;
        }
    }
    std::cout << "Source : " << inet_ntoa(this->Source.sin_addr);
    std::cout << " Destination : " << inet_ntoa(this->Destination.sin_addr);
    std::cout << std::endl;
    switch (this->iphdr->ip_protocol)
    {
        case ICMP:
            this->HandleICMP();
            std::cout << "ICMP\n";
            break;
        case TCP:
            this->HandleTCP();
            std::cout << "TCP\n";
            break;
        case UDP:
            this->HandleUDP();
            std::cout << "UDP\n";
            break;
        default:
            break;
    }
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
