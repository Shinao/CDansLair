#include "dialoginterface.h"
#include "ui_dialoginterface.h"
#include "mainwindow.h"

DialogInterface::DialogInterface(QWidget *parent) :
    QDialog(parent),
    ui(new Ui::DialogInterface)
{
    ui->setupUi(this);

    connect(ui->buttonBox, SIGNAL(accepted()), this, SLOT(startSniffing()));

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
            int i = ui->tableWidget->rowCount();
            ui->tableWidget->insertRow(i);

            insertToIndex(pAdapter->Description, i, 0);
            insertToIndex(pAdapter->IpAddressList.IpAddress.String, i, 1);
            insertToIndex(pAdapter->GatewayList.IpAddress.String, i, 2);

          pAdapter = pAdapter->Next;
        }
      } else {
        printf("Call to GetAdaptersInfo failed.\n");
      }
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
