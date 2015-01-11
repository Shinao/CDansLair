#include "dialogarp.h"
#include "ui_dialogarp.h"

Dialogarp::Dialogarp(QWidget *parent) :
    QDialog(parent),
    ui(new Ui::Dialogarp)
{
    ui->setupUi(this);

    connect(ui->buttonBox, SIGNAL(accepted()), this, SLOT(StartArp()));

    ui->lv_client->setModel(new QStringListModel());

     system("arp -a > arp_dump");

     std::ifstream  file("arp_dump");

     if (!file.is_open())
         return ;

     std::string line;
     char       ip[100];
     char       mac[100];
     while (std::getline(file, line, '\n'))
     {
#ifdef __linux__
        if (!std::sscanf(line.c_str(), "%*s %s at %s %*s", ip, mac))
            continue;
#elif _WIN32
        if (line.find("dynamic") == std::string::npos)
            continue;
       if (!std::sscanf(line.c_str(), "%s\t%s\tdynamic", ip, mac))
            continue;
#endif

         client_t *client = new client_t;

         client->ip = ip;
         client->ip.erase(std::remove(client->ip.begin(), client->ip.end(), '('));
         client->ip.erase(std::remove(client->ip.begin(), client->ip.end(), ')'));
         clients.push_back(client);

         char   smac[6];
         sscanf_s(mac, "%x:%x:%x:%x:%x:%x",  (unsigned int *) &smac[0], (unsigned int *) &smac[1], (unsigned int *) &smac[2], (unsigned int *) &smac[3], (unsigned int *) &smac[4], (unsigned int *) &smac[5]);
         memcpy(client->mac, smac, 6);
     }


     QStringList list;
     list = ((QStringListModel *) ui->lv_client->model())->stringList();
     for (std::vector<client_t *>::iterator it = clients.begin(); it != clients.end(); it++)
         list.append((*it)->ip.c_str());
     ((QStringListModel *) ui->lv_client->model())->setStringList(list);
}

Dialogarp::~Dialogarp()
{
    delete ui;
}

void    Dialogarp::StartArp()
{
    if (ui->lv_client->selectionModel()->selectedRows().count() < 2)
        return ;

    int index1 = ui->lv_client->selectionModel()->selectedRows().at(0).row();
    int index2 = ui->lv_client->selectionModel()->selectedRows().at(1).row();

    ((MainWindow *) this->parentWidget())->StartArp(clients[index1]->ip, clients[index1]->mac, clients[index2]->ip, clients[index2]->mac);

}
