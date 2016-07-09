#ifndef DIALOGARPOPTIONS_H
#define DIALOGARPOPTIONS_H

#include <QDialog>
#include "arpoptions.h"

namespace Ui {
class DialogArpOptions;
}

class DialogArpOptions : public QDialog
{
    Q_OBJECT

public:
    explicit DialogArpOptions(QWidget *parent = 0);
    ~DialogArpOptions();

    Ui::DialogArpOptions    *ui;

private slots:
    void                    SetArpOptions();

private:
    arp_options_t           _arp_options;
};

#endif // DIALOGARPOPTIONS_H
