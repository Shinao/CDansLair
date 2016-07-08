#ifndef MAINWINDOW_H
#define MAINWINDOW_H

#include <QMainWindow>
#include <QtGui>
#include <iostream>
#include <fstream>

#include "Sniffer.h"
#include "arpspoofer.h"
#include "dialogarpoptions.h"

typedef struct pcap_hdr_s {
        unsigned magic_number;   /* magic number */
        unsigned short version_major;  /* major version number */
        unsigned short version_minor;  /* minor version number */
        int  thiszone;       /* GMT to local correction */
        unsigned sigfigs;        /* accuracy of timestamps */
        unsigned snaplen;        /* max length of captured packets, in octets */
        unsigned network;        /* data link type */
} pcap_hdr_t;

typedef struct pcaprec_hdr_s {
        unsigned ts_sec;         /* timestamp seconds */
        unsigned ts_usec;        /* timestamp microseconds */
        unsigned incl_len;       /* number of octets of packet saved in file */
        unsigned orig_len;       /* actual length of packet */
} pcaprec_hdr_t;

namespace Ui {
class MainWindow;
}

class MainWindow : public QMainWindow
{
    Q_OBJECT

public:
    explicit MainWindow(QWidget *parent = 0);
    ~MainWindow();

    void    StartSniffing(const std::string &interface);
    void    ArpOptionsSet();
    void    Block(const std::string &ip);
    void    Unblock(const std::string &ip);
    void    StartArp(const std::string &ip1, char *mac1, const std::string &ip2, char *mac2);
    std::list<std::string>      _blocked_ip;

private:
    void    insertPacket(SniffedPacket &packet);
    void    insertToIndex(const QString &protocol, const QString &str, int row, int col);

    ArpSpoofer                  _arp_spoofer;
    char                        _local_mac[6];
    std::string                 _local_ip;
    std::list<SniffedPacket *>  Packets;
    QThread                     *thread;
    Sniffer                     *sniffer;
    Ui::MainWindow              *ui;
    std::string                 interface;
    int                         counter;
    DialogArpOptions            *_dialog_arp_options;

private slots:
    void    ToggleSniffer();
    void    getNewPackets();
    void    Clear();
    void    Save();
    void    Load();
    void    ArpPoisoning();
    void    BlockIp();
    void    ArpOptions();
};

#endif // MAINWINDOW_H
