#include "dialogarpoptions.h"
#include "ui_dialogarpoptions.h"
#include "mainwindow.h"

DialogArpOptions::DialogArpOptions(QWidget *parent) :
    QDialog(parent),
    ui(new Ui::DialogArpOptions)
{
    ui->setupUi(this);

    connect(ui->buttonBox, SIGNAL(accepted()), this, SLOT(StartArp()));
    connect(ui->buttonBox, SIGNAL(rejected()), this, SLOT(close()));
}

DialogArpOptions::~DialogArpOptions()
{
    delete ui;
}

void    DialogArpOptions::SetArpOptions()
{
    ((MainWindow *) this->parentWidget())->ArpOptionsSet();
    close();
}
