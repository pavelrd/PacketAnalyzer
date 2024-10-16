TEMPLATE = app
CONFIG += console c++11
CONFIG -= app_bundle
CONFIG -= qt

SOURCES += \
        main.cpp \
    analyze_packet.cpp

LIBS += -lnetfilter_queue -lpthread

HEADERS += \
    analyze_packet.hpp \
    config.hpp \
    icmp_payloads.hpp
