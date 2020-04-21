TEMPLATE = app
CONFIG += console c++11
CONFIG -= app_bundle
CONFIG -= qt
LIBS += -lpcap

SOURCES += \
        ip.cpp \
        main.cpp

HEADERS += \
    arp.h \
    ip.h \
