#include "dialoginterface.h"
#include "ui_dialoginterface.h"
#include "mainwindow.h"
#include "Sniffer.h"

DialogInterface::DialogInterface(QWidget *parent) :
    QDialog(parent),
    ui(new Ui::DialogInterface)
{
    ui->setupUi(this);

    connect(ui->buttonBox, SIGNAL(accepted()), this, SLOT(startSniffing()));

#ifdef _WIN32
    PIP_ADAPTER_INFO pAdapterInfo;
      pAdapterInfo = (IP_ADAPTER_INFO *) malloc(sizeof(IP_ADAPTER_INFO));
      ULONG buflen = sizeof(IP_ADAPTER_INFO);

      if(GetAdaptersInfo(pAdapterInfo, &buflen) == ERROR_BUFFER_OVERFLOW) {
        free(pAdapterInfo);
        pAdapterInfo = (IP_ADAPTER_INFO *) malloc(buflen);
      }

      if(GetAdaptersInfo(pAdapterInfo, &buflen) == NO_ERROR) {
        PIP_ADAPTER_INFO pAdapter = pAdapterInfo;
        while (pAdapter) {
            insertInterface(pAdapter->Description, pAdapter->IpAddressList.IpAddress.String, pAdapter->GatewayList.IpAddress.String);

          pAdapter = pAdapter->Next;
        }
      } else {
        printf("Call to GetAdaptersInfo failed.\n");
      }
#elif __linux__
    struct ifaddrs *ifaddr, *ifa;
    int family, s, n;
    char host[NI_MAXHOST];

    if (getifaddrs(&ifaddr) == -1) {
      perror("getifaddrs");
      return;
    }

    for (ifa = ifaddr, n = 0; ifa != NULL; ifa = ifa->ifa_next, n++) {
      family = ifa->ifa_addr->sa_family;
      if (ifa->ifa_addr == NULL || family != AF_INET)
        continue;

        s = getnameinfo(ifa->ifa_addr,
                        (family == AF_INET) ? sizeof(struct sockaddr_in) :
                        sizeof(struct sockaddr_in6),
                        host, NI_MAXHOST,
                        NULL, 0, NI_NUMERICHOST);

        if (s != 0)
            continue;
        insertInterface(ifa->ifa_name, host, "");
    }

    freeifaddrs(ifaddr);
#endif
}

void DialogInterface::insertInterface(const char *name, const char *ip, const char *gateway)
{
    int i = ui->tableWidget->rowCount();
    ui->tableWidget->insertRow(i);

    insertToIndex(name, i, 0);
    insertToIndex(ip, i, 1);
    insertToIndex(gateway, i, 2);
}

void    DialogInterface::startSniffing()
{
    QItemSelectionModel *select = ui->tableWidget->selectionModel();

    if (select->hasSelection())
        ((MainWindow *)this->parentWidget())->StartSniffing(ui->tableWidget->item(select->selectedRows().at(0).row(), 1)->text().toStdString());
}

void    DialogInterface::insertToIndex(const QString &str, int row, int col)
{
    QTableWidgetItem *item = new QTableWidgetItem(str);
    item->setFlags(Qt::ItemIsSelectable | Qt::ItemIsEnabled);
    if (col != 4)
        item->setTextAlignment(Qt::AlignCenter);
    ui->tableWidget->setItem(row, col, item);
}

DialogInterface::~DialogInterface()
{
    delete ui;
}
