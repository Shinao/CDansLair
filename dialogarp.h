#ifndef DIALOGARP_H
#define DIALOGARP_H

#include <QDialog>
#include "mainwindow.h"

namespace Ui {
class Dialogarp;
}

class Dialogarp : public QDialog
{
    Q_OBJECT

public:
    explicit Dialogarp(QWidget *parent = 0);
    ~Dialogarp();

private:
    Ui::Dialogarp *ui;
    std::vector<client_t *>   clients;

private slots:
    void    StartArp();
};

#endif // DIALOGARP_H
