#ifndef DIALOGINTERFACE_H
#define DIALOGINTERFACE_H

#include <QDialog>

namespace Ui {
class DialogInterface;
}

class DialogInterface : public QDialog
{
    Q_OBJECT

public:
    explicit DialogInterface(QWidget *parent = 0);
    ~DialogInterface();

private:
    Ui::DialogInterface *ui;
};

#endif // DIALOGINTERFACE_H
