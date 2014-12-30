#ifndef SNIFFER_H_INCLUDED
#define SNIFFER_H_INCLUDED

#ifdef __linux__
#include <arpa/inet.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <unistd.h>
#include <netdb.h>
#include <linux/if_ether.h>
#include <net/if.h>
#include <sys/ioctl.h>
#include <netpacket/packet.h>
#include <net/ethernet.h>

#elif _WIN32
#include <WinSock2.h>
#include <windows.h>
#endif

#include <string>
#include <stdexcept>
#include <algorithm>
#include <fstream>
#include <iostream>
#include <sstream>
#include <vector>
#include <cstdint>
#include <QtDebug>
#include <QObject>
#include <QMutex>

#define ICMP 1
#define TCP 6
#define UDP 17

#ifdef __linux__
#define SOCKET int
#define INVALID_SOCKET -1
#define SOCKET_ERROR   -1
typedef char WCHAR;
typedef char CHAR;
typedef WCHAR *LPWSTR;
typedef CHAR *LPSTR;
#ifdef UNICODE
 typedef LPWSTR LPTSTR;
#else
 typedef LPSTR LPTSTR;
#endif

#endif


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
  uint8_t type;                /* message type */
  uint8_t code;                /* type sub-code */
  uint16_t checksum;
  union
  {
    struct
    {
      uint16_t id;
      uint16_t sequence;
    } echo;                     /* echo datagram */
    uint32_t   gateway;        /* gateway address */
    struct
    {
      uint16_t __unused;
      uint16_t mtu;
    } frag;                     /* path mtu discovery */
  } un;
} ICMP_HDR;


typedef struct udp_hdr
{
    unsigned short source_port;
    unsigned short dest_port;
    unsigned short udp_length;
    unsigned short udp_checksum;
} UDP_HDR;

struct SniffedPacket
{
    std::string ip_source;
    std::string ip_dest;
    int         size;
    QString     info;
    QString     protocol;
    char        *data;
};

class Sniffer : public QObject
{
    Q_OBJECT

    public:
        Sniffer();
        ~Sniffer();
        int         GetInterface();
        void        SetInterface(int Interf);
        bool        Initialize();
        void        DeInitialize();

        // Manipulation
        void        Stop();
        char        *data;
        std::string GetIP(std::string Address);

        // Thread
        std::list<SniffedPacket *> Packets;
        QMutex                     mutex;

public slots:
        void Start();

    private:
        // Socket
        SOCKET              SniffSocket;
        int                 Interface;
        std::vector<std::string> SourceIP;
        std::vector<std::string> DestinationIP;
        bool                Initialized;
        bool                Sniffing;
        struct sockaddr_in  Source, Destination;

        // Handle packets
        void        Sniff();
        void        ManagePacket();
        void        ICMPPacket(SniffedPacket &packet);
        void        TCPPacket(SniffedPacket &packet);
        void        UDPPacket(SniffedPacket &packet);
        std::string PrintBuffer(char* data, int s);
        bool        ManageError(const std::string &msg);

        // Current packet info
        int         data_size;
        bool        Filter;
        bool        SniffSource;
        bool        SniffDestination;
        IPV4_HDR    *iphdr;
        TCP_HDR     *tcphdr;
        ICMP_HDR    *icmphdr;
        UDP_HDR     *udphdr;
};

#endif // SNIFFER_H_INCLUDED
