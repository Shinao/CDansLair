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
    void    insertToIndex(const QString &str, int row, int col);
    void    insertInterface(const char *name, const char *ip, const char *gateway);
    Ui::DialogInterface *ui;

private slots:
    void    startSniffing();
};

#endif // DIALOGINTERFACE_H