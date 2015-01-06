#ifndef MAINWINDOW_H
#define MAINWINDOW_H

#include <QMainWindow>
#include <QtGui>
#include <iostream>
#include <fstream>
#include "Sniffer.h"

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

typedef struct client_s {
    std::string ip;
    char        mac[6];
}               client_t;

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

private:
    void    insertPacket(SniffedPacket &packet);
    void    insertToIndex(const QString &str, int row, int col);
    void    checkArp(SniffedPacket &packet);
    void    refreshArp();

    char                        mac[6];
    std::list<SniffedPacket *>  Packets;
    QThread                     *thread;
    Sniffer                     *sniffer;
    Ui::MainWindow              *ui;
    client_t                    *client1;
    client_t                    *client2;
    std::string                 interface;
    int                         counter;

private slots:
    void    ToggleSniffer();
    void    getNewPackets();
    void    Clear();
    void    Save();
    void    Load();
    void    ArpPoisoning();
};

#endif // MAINWINDOW_H
