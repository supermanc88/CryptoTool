QT       += core gui

greaterThan(QT_MAJOR_VERSION, 4): QT += widgets

CONFIG += c++17

INCLUDEPATH += .
INCLUDEPATH += /opt/homebrew/Cellar/openssl@3/3.6.0/include

LIBS += /opt/homebrew/Cellar/openssl@3/3.6.0/lib/libcrypto.a

# You can make your code fail to compile if it uses deprecated APIs.
# In order to do so, uncomment the following line.
#DEFINES += QT_DISABLE_DEPRECATED_BEFORE=0x060000    # disables all the APIs deprecated before Qt 6.0.0

SOURCES += \
    crypto/digest_service.cpp \
    crypto/dsa_service.cpp \
    crypto/mac_service.cpp \
    crypto/rsa_service.cpp \
    crypto/sm2_service.cpp \
    crypto/sm3_service.cpp \
    crypto/sm4_service.cpp \
    crypto/stream_service.cpp \
    crypto/utility_service.cpp \
    main.cpp \
    mainwindow.cpp \
    shared/crypto_common.cpp \
    widgets/digestpage.cpp \
    widgets/dsapage.cpp \
    widgets/macpage.cpp \
    widgets/rsapage.cpp \
    widgets/sm2page.cpp \
    widgets/sm3page.cpp \
    widgets/sm4page.cpp \
    widgets/streampage.cpp \
    widgets/utilitypage.cpp

HEADERS += \
    crypto/digest_service.h \
    crypto/dsa_service.h \
    crypto/mac_service.h \
    crypto/rsa_service.h \
    crypto/sm2_service.h \
    crypto/sm3_service.h \
    crypto/sm4_service.h \
    crypto/stream_service.h \
    crypto/utility_service.h \
    mainwindow.h \
    shared/crypto_common.h \
    widgets/digestpage.h \
    widgets/dsapage.h \
    widgets/macpage.h \
    widgets/pagechrome.h \
    widgets/rsapage.h \
    widgets/sm2page.h \
    widgets/sm3page.h \
    widgets/sm4page.h \
    widgets/streampage.h \
    widgets/utilitypage.h

FORMS += \
    mainwindow.ui

# Default rules for deployment.
qnx: target.path = /tmp/$${TARGET}/bin
else: unix:!android: target.path = /opt/$${TARGET}/bin
!isEmpty(target.path): INSTALLS += target
