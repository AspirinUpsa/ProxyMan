#QT += core gui widgets network
#CONFIG += c++11
#SOURCES += main.cpp
#TARGET = ProxyMan

QT += core gui widgets network
CONFIG += c++11
SOURCES += main.cpp
TARGET = ProxyMan

# Подключение библиотеки wininet для MinGW и MSVC
win32 {
    LIBS += -lwininet
}
