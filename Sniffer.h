#ifndef SNIFFER_H_INCLUDED
#define SNIFFER_H_INCLUDED

#include <WinSock2.h>
#include <windows.h>
#include <string>
#include <stdexcept>
#include <algorithm>
#include <fstream>
#include <iostream>
#include <sstream>
#include <vector>
#include <cstdint>

#define LogError std::cout<<"Error On Line: "<<__LINE__<<" in File: "<<__FILE__<<"\n"
std::string ErrorMessage(std::uint32_t Error, bool Throw);

#define ICMP 1
#define TCP 6
#define UDP 17



typedef struct ip_hdr
{
    unsigned char ip_header_len :4;
    unsigned char ip_version :4;
    unsigned char ip_tos;
    unsigned short ip_total_length;
    unsigned short ip_id;
    unsigned char ip_frag_offset :5;
    unsigned char ip_more_fragment :1;
    unsigned char ip_dont_fragment :1;
    unsigned char ip_reserved_zero :1;
    unsigned char ip_frag_offset1;
    unsigned char ip_ttl;
    unsigned char ip_protocol;
    unsigned short ip_checksum;
    unsigned int ip_srcaddr;
    unsigned int ip_destaddr;
} IPV4_HDR;

typedef struct tcp_hdr
{
    unsigned short source_port;
    unsigned short dest_port;
    unsigned int sequence;
    unsigned int acknowledge;
    unsigned char ns :1;
    unsigned char reserved_part1:3;
    unsigned char data_offset:4;
    unsigned char fin :1;
    unsigned char syn :1;
    unsigned char rst :1;
    unsigned char psh :1;
    unsigned char ack :1;
    unsigned char urg :1;
    unsigned char ecn :1;
    unsigned char cwr :1;
    unsigned short window;
    unsigned short checksum;
    unsigned short urgent_pointer;
} TCP_HDR;

typedef struct icmp_hdr
{
    BYTE type;
    BYTE code;
    USHORT checksum;
    USHORT id;
    USHORT seq;
} ICMP_HDR;

typedef struct udp_hdr
{
    unsigned short source_port;
    unsigned short dest_port;
    unsigned short udp_length;
    unsigned short udp_checksum;
} UDP_HDR;

class Sniffer
{
    public:
        Sniffer();
        ~Sniffer();
        void RemoveSourceIP(std::string OldIP);
        void RemoveDestinationIP(std::string OldIP);
        void AddDestinationIP(std::string NewIP);
        void AddSourceIP(std::string NewIP);
        int GetInterface();
        void SetInterface(int Interf);
        bool Initialize();
        void DeInitialize();
        void Start();
        void Stop();
        void FilterIP(bool FilterIPs);
        void ListenSource(bool Listen);
        void ListenDestination(bool Listen);
        char *Buffer;
        std::string GetIP(std::string Address);
       // void Test();
    private:
        SOCKET SniffSocket;
        int Interface;
        std::vector<std::string> SourceIP;
        std::vector<std::string> DestinationIP;
        bool Initialized;
        bool Sniffing;
        struct sockaddr_in Source, Destination;
        void Error();
        void Sniff();
        void HandleICMP();
        void HandleTCP();
        void HandleUDP();
        void Packet();
        bool StringArrayContains(std::vector<std::string> Array, std::string Element);
        std::string PrintBuffer(char* data, int s);
        int BuffSize;
        bool Filter;
        bool SniffSource;
        bool SniffDestination;
        IPV4_HDR *iphdr;
        TCP_HDR *tcphdr;
        ICMP_HDR *icmphdr;
        UDP_HDR *udphdr;
};


class Test
{
public:
    Test();
};

#endif // SNIFFER_H_INCLUDED
