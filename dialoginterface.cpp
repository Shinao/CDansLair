#include "dialoginterface.h"
#include "ui_dialoginterface.h"

DialogInterface::DialogInterface(QWidget *parent) :
    QDialog(parent),
    ui(new Ui::DialogInterface)
{
    ui->setupUi(this);
}

DialogInterface::~DialogInterface()
{
    delete ui;
}
