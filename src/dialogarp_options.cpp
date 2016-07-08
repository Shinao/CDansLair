#include "dialogarp_options.h"
#include "ui_dialogarp_options.h"

Dialogarp_options::Dialogarp_options(QWidget *parent) :
    QDialog(parent),
    ui(new Ui::Dialogarp_options)
{
    ui->setupUi(this);

    connect(ui->buttonBox, SIGNAL(accepted()), this, SLOT(SetOptions()));
}

Dialogarp_options::~Dialogarp_options()
{
    delete ui;
}

void    Dialogarp_options::SetOptions()
{

}
