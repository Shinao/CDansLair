#include "dialogarpoptions.h"
#include "ui_dialogarpoptions.h"
#include "mainwindow.h"

DialogArpOptions::DialogArpOptions(QWidget *parent) :
    QDialog(parent),
    ui(new Ui::DialogArpOptions)
{
    ui->setupUi(this);

    connect(ui->buttonBox, SIGNAL(accepted()), this, SLOT(SetArpOptions()));
    connect(ui->buttonBox, SIGNAL(rejected()), this, SLOT(close()));
}

DialogArpOptions::~DialogArpOptions()
{
    delete ui;
}

void    DialogArpOptions::SetArpOptions()
{
    _arp_options.download_rate = ui->le_download_rate->text().toInt();
    _arp_options.upload_rate = ui->le_upload_rate->text().toInt();
    _arp_options.replace_from = ui->le_replace_from->text().toStdString();
    _arp_options.replace_to = ui->le_replace_to->text().toStdString();
    _arp_options.redirect_traffic = ui->cb_redirect_traffic->isChecked();
    _arp_options.remove_encoding = ui->cb_remove_gzip->isChecked();

    ((MainWindow *) this->parentWidget())->ArpOptionsSet(&_arp_options);
    close();
}
