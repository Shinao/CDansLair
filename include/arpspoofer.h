#ifndef ARPSPOOFER_H
#define ARPSPOOFER_H

#include "Sniffer.h"

typedef struct client_s {
    std::string ip;
    char        mac[6];
}               client_t;

class ArpSpoofer
{
public:
    ArpSpoofer();
    ~ArpSpoofer();
    void            Initialize();
    void            Start(const std::string &local_ip, char *local_mac, const std::string &ip1, char *mac1, const std::string &ip2, char *mac2);
    void            Stop();
    void            ManageNewPacket(SniffedPacket &packet);
    void            SendArpRedirectRequest();
    int             ReplaceTCPText(SniffedPacket &packet, const std::string &find, const std::string &replace);
    void            RedirectTraffic(bool redirect);
    void            RemoveHttpEncoding(bool remove_encoding);
    void            ThrottleTraffic(int upload_rate, int download_rate);
    void            ReplaceHttpText(const std::string &from, const std::string &to);

private:
    std::string     _local_ip;
    char            *_local_mac;
    int             _socket_arp;
    client_t        *_client1;
    client_t        *_client2;

    std::string     _replace_from;
    std::string     _replace_to;
    bool            _remove_encoding;
    bool            _redirect_traffic;
    int             _download_rate;
    int             _upload_rate;
};

#endif // ARPSPOOFER_H
