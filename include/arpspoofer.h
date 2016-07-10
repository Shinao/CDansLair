#ifndef ARPSPOOFER_H
#define ARPSPOOFER_H

#include "Sniffer.h"
#include "arpoptions.h"
#include <QElapsedTimer>

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
    void            Start(const std::string &interface, const std::string &local_ip, char *local_mac, const std::string &ip1, char *mac1, const std::string &ip2, char *mac2);
    void            Stop();
    void            ManageNewPacket(SniffedPacket &packet);
    void            SendArpRedirectRequest();
    int             ReplaceTCPText(SniffedPacket &packet, const std::string &find, const std::string &replace);
    void            SetArpOptions(arp_options_t *arp_options);

private:
    bool            ThrottleNetworkRateFor(SniffedPacket &packet, bool uploading);

    std::string     _interface;
    std::string     _local_ip;
    char            *_local_mac;
    int             _socket_arp;
    client_t        *_client1;
    client_t        *_client2;
    arp_options_t   *_arp_options;
    int             _kb_downloaded_last_second;
    int             _kb_uploaded_last_second;
    QElapsedTimer   _timer;
};

#endif // ARPSPOOFER_H
