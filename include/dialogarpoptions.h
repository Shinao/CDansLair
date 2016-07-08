#ifndef DIALOGARPOPTIONS_H
#define DIALOGARPOPTIONS_H

#include <QDialog>

namespace Ui {
class DialogArpOptions;
}

class DialogArpOptions : public QDialog
{
    Q_OBJECT

public:
    explicit DialogArpOptions(QWidget *parent = 0);
    ~DialogArpOptions();

    Ui::DialogArpOptions *ui;

private slots:
    void    SetArpOptions();
};

#endif // DIALOGARPOPTIONS_H
