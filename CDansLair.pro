#-------------------------------------------------
#
# Project created by QtCreator 2014-11-10T11:34:48
#
#-------------------------------------------------



QT       += core gui
LIBS    += -lws2_32
DEFINES += WIN32_LEAN_AND_MEAN

greaterThan(QT_MAJOR_VERSION, 4): QT += widgets

TARGET = CDansLair
TEMPLATE = app


SOURCES += main.cpp\
        mainwindow.cpp \
    Sniffer.cpp

HEADERS  += mainwindow.h \
    Sniffer.h

FORMS    += mainwindow.ui
