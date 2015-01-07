#ifndef DIALOGBLOCK_H
#define DIALOGBLOCK_H

#include <QDialog>

namespace Ui {
class DialogBlock;
}

class DialogBlock : public QDialog
{
    Q_OBJECT

public:
    explicit DialogBlock(QWidget *parent = 0);
    ~DialogBlock();

private:
    Ui::DialogBlock *ui;

private slots:
    void    block();
    void    unblock();
};

#endif // DIALOGBLOCK_H
