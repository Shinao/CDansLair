#-------------------------------------------------
#
# Project created by QtCreator 2014-11-10T11:34:48
#
#-------------------------------------------------



QT       += core gui

DEFINES += WIN32_LEAN_AND_MEAN

CONFIG += c++11
unix:QMAKE_CXXFLAGS += -std=c++11
win32:LIBS += -lws2_32
QMAKE_CXXFLAGS_CXX11    = -std=c++11

INCLUDEPATH += include \
            src \
            forms

greaterThan(QT_MAJOR_VERSION, 4): QT += widgets

TARGET = CDansLair
TEMPLATE = app

SOURCES += src/main.cpp \
    src/dialogarp.cpp \
    src/dialogblock.cpp \
    src/dialoginterface.cpp \
    src/mainwindow.cpp \
    src/Sniffer.cpp \
    src/arpspoofer.cpp \
    src/dialogarp_options.cpp

HEADERS += include/dialogarp.h \
    include/dialogblock.h \
    include/dialoginterface.h \
    include/mainwindow.h \
    include/Sniffer.h \
    include/arpspoofer.h \
    include/memoryutil.h \
    include/dialogarp_options.h

FORMS += forms/mainwindow.ui \
    forms/dialogblock.ui \
    forms/dialogarp.ui \
    forms/dialoginterface.ui \
    forms/dialogarp_options.ui
