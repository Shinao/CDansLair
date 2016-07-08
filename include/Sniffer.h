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
#include <linux/if_link.h>
#include <ifaddrs.h>
#include <netinet/if_ether.h>

#elif _WIN32
#include <WinSock2.h>
#include <windows.h>
#include <iphlpapi.h>
#include <ws2tcpip.h>

#pragma comment(lib, "iphlpapi.lib")
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
#include <map>
#include <cstdio>
#include <cstdlib>
#include <cstring>

#define ICMP 1
#define TCP 6
#define UDP 17
#define ETHER_HDR_SIZE 14
#define IP4LEN 4
#define PKTLEN sizeof(struct ether_header) + sizeof(struct ether_arp)

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

typedef struct eth_hdr {
    char ether_dhost[6]; /* Destination host address */
    char ether_shost[6]; /* Source host address */
    short ether_type; /* IP? ARP? RARP? etc */
} eth_hdr_t;

typedef struct ip_hdr
{
#if __BYTE_ORDER == __LITTLE_ENDIAN
    unsigned char ip_header_len :4;
    unsigned char ip_version :4;
#elif __BYTE_ORDER == __BIG_ENDIAN
    unsigned char ip_version :4;
    unsigned char ip_header_len :4;
#else
# error "Your systems ENDIANNESS is broken, please fix!"
#endif
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
} IP_HDR;

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
    int         proto_id;
    bool        has_ether_hdr;
    int         sport;
    int         dport;
    int         iphdr_size;
};

class Sniffer : public QObject
{
    Q_OBJECT

    public:
        Sniffer();
        ~Sniffer();

        bool                    IsSniffing();
        bool                    Initialize(const std::string &interface);
        void                    DeInitialize();
        const std::string &     GetInterface();

        // Manipulation
        static void             ManagePacket(char *data, int data_size, bool pcap = false);
        void                    Stop();
        char                    *data;
        std::string             GetIP(std::string Address);

        // Thread
        static std::list<SniffedPacket *> Packets;
        static QMutex                     mutex;

public slots:
        void                Start();

    protected:
        // Socket
        SOCKET              SniffSocket;
        std::string         Interface;
        int                 InterfaceStatus;
        bool                Initialized;
        bool                Sniffing;
        struct sockaddr_in  Source, Destination;

        // Handle packets
        void                Sniff();
        bool                ManageError(const std::string &msg);
        static void        ICMPPacket(SniffedPacket &packet);
        static void        TCPPacket(SniffedPacket &packet);
        static void        UDPPacket(SniffedPacket &packet);

        // Current packet info
        int                 data_size;
        static IP_HDR       *iphdr;
        static TCP_HDR      *tcphdr;
        static ICMP_HDR     *icmphdr;
        static UDP_HDR      *udphdr;
        static std::map<int, std::string>  ProtocolInfo;
};

#endif // SNIFFER_H_INCLUDED
