#ifndef DIALOGARP_H
#define DIALOGARP_H

#include <QDialog>

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
};

#endif // DIALOGARP_H
