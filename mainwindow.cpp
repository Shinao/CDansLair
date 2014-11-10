#include "mainwindow.h"
#include "ui_mainwindow.h"
#include "Sniffer.h"

MainWindow::MainWindow(QWidget *parent) :
    QMainWindow(parent),
    ui(new Ui::MainWindow)
{
    ui->setupUi(this);

    sniffer = new Sniffer();
    QTimer *timer = new QTimer(this);
    timer->setInterval(100);
    timer->start(100);
    connect(timer, SIGNAL(timeout()), this, SLOT(getNewPackets()));
//      try
//      {
//          s.SetInterface(0);
//          s.Initialize();
//          s.Start();

//      }
//      catch (std::exception &e)
//      {
//          std::cout<<"\nERROR: "<<e.what();
//          s.Stop();
//          s.DeInitialize();
//      }
}

MainWindow::~MainWindow()
{
    delete ui;
}

void    MainWindow::getNewPackets()
{

}
