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
    explicit DialogInterface(QWidget *parent, std::string &ip, char *mac);
    ~DialogInterface();

private:
    void    insertToIndex(const QString &str, int row, int col);
    void    insertInterface(const char *name, const char *ip, const char *gateway);
    Ui::DialogInterface *ui;

    std::string &_ip;
    char        *_mac;

private slots:
    void    startSniffing();
};

#endif // DIALOGINTERFACE_H
