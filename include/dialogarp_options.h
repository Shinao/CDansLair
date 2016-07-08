#ifndef DIALOGARP_OPTIONS_H
#define DIALOGARP_OPTIONS_H

#include <QDialog>
#include "mainwindow.h"

namespace Ui {
class Dialogarp_options;
}

class Dialogarp_options : public QDialog
{
    Q_OBJECT

public:
    explicit Dialogarp_options(QWidget *parent = 0);
    ~Dialogarp_options();

private:
    Ui::Dialogarp_options *ui;

private slots:
    void    SetOptions();
};

#endif // DIALOGARP_OPTIONS_H
