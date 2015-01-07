#include "dialogblock.h"
#include "ui_dialogblock.h"
#include "mainwindow.h"

DialogBlock::DialogBlock(QWidget *parent) :
    QDialog(parent),
    ui(new Ui::DialogBlock)
{
    ui->setupUi(this);

    connect(ui->pb_block, SIGNAL(clicked()), this, SLOT(block()));
    connect(ui->pb_unblock, SIGNAL(clicked()), this, SLOT(unblock()));

    ui->lv_ip->setModel(new QStringListModel());

    QStringList list;
    list = ((QStringListModel *) ui->lv_ip->model())->stringList();
    std::list<std::string> &ips = ((MainWindow *) this->parentWidget())->_blocked_ip;
    for (std::list<std::string>::iterator it = ips.begin(); it != ips.end(); it++)
        list.append((*it).c_str());
    ((QStringListModel *) ui->lv_ip->model())->setStringList(list);
}

DialogBlock::~DialogBlock()
{
    delete ui;
}

void    DialogBlock::block()
{
    QStringList list;
    list = ((QStringListModel *) ui->lv_ip->model())->stringList();
    list.append(ui->le_ip->text());
    ((QStringListModel *) ui->lv_ip->model())->setStringList(list);

    ((MainWindow *) this->parentWidget())->Block(ui->le_ip->text().toStdString());
}

void    DialogBlock::unblock()
{
    if (ui->lv_ip->selectionModel()->selectedRows().count() == 0)
        return ;


    QStringList list;
    list = ((QStringListModel *) ui->lv_ip->model())->stringList();

    ((MainWindow *) this->parentWidget())->Unblock(list.at(ui->lv_ip->selectionModel()->selectedRows().at(0).row()).toStdString());

    list.removeAt(ui->lv_ip->selectionModel()->selectedRows().at(0).row());
    ((QStringListModel *) ui->lv_ip->model())->setStringList(list);
}

