#ifndef MAINWINDOW_H
#define MAINWINDOW_H

#include <QMainWindow>
#include <QtGui>
#include "Sniffer.h"

namespace Ui {
class MainWindow;
}

class MainWindow : public QMainWindow
{
    Q_OBJECT

public:
    explicit MainWindow(QWidget *parent = 0);
    ~MainWindow();

private:
    void    insertToIndex(const QString &str, int row, int col);

    QThread *thread;
    Sniffer *sniffer;
    Ui::MainWindow *ui;

private slots:
    void    getNewPackets();
};

#endif // MAINWINDOW_H
