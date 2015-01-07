#include "dialogarp.h"
#include "ui_dialogarp.h"

Dialogarp::Dialogarp(QWidget *parent) :
    QDialog(parent),
    ui(new Ui::Dialogarp)
{
    ui->setupUi(this);
}

Dialogarp::~Dialogarp()
{
    delete ui;
}
