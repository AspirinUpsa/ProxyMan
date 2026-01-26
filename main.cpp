// main.cpp
// Программа для управления системным прокси Windows через системный трей
// Copyright (C) 2026 POWer, Samara
// Все права защищены
//
// Описание: Приложение позволяет быстро переключать прокси-соединение
//           одним кликом мыши и управлять настройками прокси-сервера

#include <QApplication>
#include <QSystemTrayIcon>
#include <QMenu>
#include <QAction>
#include <QPainter>
#include <QPixmap>
#include <QNetworkProxy>
#include <QNetworkProxyFactory>
#include <QSettings>
#include <QMessageBox>
#include <QUrl>
#include <QDialog>
#include <QVBoxLayout>
#include <QHBoxLayout>
#include <QLineEdit>
#include <QPushButton>
#include <QLabel>
#include <QSpinBox>
#include <QCheckBox>
#include <QGroupBox>
#include <QCoreApplication>
#include <QDir>
#include <QSharedMemory>
#include <QSystemSemaphore>

#ifdef Q_OS_WIN
#include <windows.h>
#include <wininet.h>  // Для работы с системными настройками прокси Windows
#endif

//==============================================================================
// Класс для проверки единственного экземпляра приложения
//==============================================================================
class SingleInstanceGuard {
public:
    SingleInstanceGuard(const QString &key) : key(key) {
        // Создаём семафор для синхронизации между процессами
        semaphore = new QSystemSemaphore(key + "_semaphore", 1);
        semaphore->acquire();

#ifndef Q_OS_WIN
        // В Unix-системах разделяемая память может оставаться после краша
        // Пытаемся присоединиться к существующей памяти
        QSharedMemory fix(key);
        fix.attach();
#endif

        // Создаём разделяемую память
        sharedMemory = new QSharedMemory(key);

        // Пытаемся создать блок разделяемой памяти
        if (!sharedMemory->create(1)) {
            // Если не удалось создать - значит приложение уже запущено
            isAnotherInstanceRunning = true;
        } else {
            isAnotherInstanceRunning = false;
        }

        semaphore->release();
    }

    ~SingleInstanceGuard() {
        if (sharedMemory) {
            sharedMemory->detach();
            delete sharedMemory;
        }
        if (semaphore) {
            delete semaphore;
        }
    }

    bool isAnotherRunning() const {
        return isAnotherInstanceRunning;
    }

private:
    QString key;
    QSharedMemory *sharedMemory;
    QSystemSemaphore *semaphore;
    bool isAnotherInstanceRunning;
};

//==============================================================================
// Класс для управления автозагрузкой приложения в Windows
//==============================================================================
class AutostartManager {
public:
    //--------------------------------------------------------------------------
    // Проверка, находится ли приложение в автозагрузке
    //--------------------------------------------------------------------------
    static bool isInAutostart() {
        QSettings settings("HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\Run",
                          QSettings::NativeFormat);
        return settings.contains("ProxyMan");
    }

    //--------------------------------------------------------------------------
    // Добавление приложения в автозагрузку Windows
    //--------------------------------------------------------------------------
    static bool addToAutostart() {
        // Получаем полный путь к исполняемому файлу
        QString appPath = QDir::toNativeSeparators(QCoreApplication::applicationFilePath());

        // Добавляем кавычки для корректной работы с путями, содержащими пробелы
        appPath = "\"" + appPath + "\"";

        // Записываем в реестр Windows (ветка автозагрузки)
        QSettings settings("HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\Run",
                          QSettings::NativeFormat);
        settings.setValue("ProxyMan", appPath);
        settings.sync();

        return settings.status() == QSettings::NoError;
    }

    //--------------------------------------------------------------------------
    // Удаление приложения из автозагрузки Windows
    //--------------------------------------------------------------------------
    static bool removeFromAutostart() {
        QSettings settings("HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\Run",
                          QSettings::NativeFormat);
        settings.remove("ProxyMan");
        settings.sync();

        return settings.status() == QSettings::NoError;
    }
};

//==============================================================================
// Диалоговое окно настроек прокси-сервера
//==============================================================================
class ProxySettingsDialog : public QDialog {
    Q_OBJECT
public:
    // Конструктор диалога
    ProxySettingsDialog(QWidget *parent = nullptr) : QDialog(parent) {
        setWindowTitle("Настройки прокси сервера");
        setMinimumWidth(400);

        QVBoxLayout *mainLayout = new QVBoxLayout(this);

        //----------------------------------------------------------------------
        // Группа основных настроек прокси
        //----------------------------------------------------------------------
        QGroupBox *proxyGroup = new QGroupBox("Параметры прокси сервера", this);
        QVBoxLayout *proxyLayout = new QVBoxLayout(proxyGroup);

        // Поле ввода адреса прокси-сервера
        QHBoxLayout *hostLayout = new QHBoxLayout();
        hostLayout->addWidget(new QLabel("Адрес сервера:"));
        hostEdit = new QLineEdit(this);
        hostEdit->setPlaceholderText("Например: 192.168.1.1 или proxy.company.com");
        hostLayout->addWidget(hostEdit);
        proxyLayout->addLayout(hostLayout);

        // Поле ввода порта прокси-сервера
        QHBoxLayout *portLayout = new QHBoxLayout();
        portLayout->addWidget(new QLabel("Порт:"));
        portSpin = new QSpinBox(this);
        portSpin->setRange(1, 65535);  // Диапазон допустимых портов
        portSpin->setValue(8080);      // Стандартный порт прокси по умолчанию
        portSpin->setMinimumWidth(100);
        portLayout->addWidget(portSpin);
        portLayout->addStretch();
        proxyLayout->addLayout(portLayout);

        // Поле ввода исключений (адреса, для которых не используется прокси)
        proxyLayout->addWidget(new QLabel("Не использовать прокси для (через ;):"));
        exceptionsEdit = new QLineEdit(this);
        exceptionsEdit->setPlaceholderText("localhost;127.0.0.1;*.local");
        proxyLayout->addWidget(exceptionsEdit);

        // Чекбокс для автоматического обхода прокси для локальных адресов
        bypassLocalCheck = new QCheckBox("Не использовать прокси для локальных адресов", this);
        bypassLocalCheck->setChecked(true);
        proxyLayout->addWidget(bypassLocalCheck);

        mainLayout->addWidget(proxyGroup);

        //----------------------------------------------------------------------
        // Группа настроек аутентификации (опциональная)
        //----------------------------------------------------------------------
        QGroupBox *authGroup = new QGroupBox("Аутентификация (опционально)", this);
        QVBoxLayout *authLayout = new QVBoxLayout(authGroup);

        // Поле ввода имени пользователя
        QHBoxLayout *userLayout = new QHBoxLayout();
        userLayout->addWidget(new QLabel("Пользователь:"));
        userEdit = new QLineEdit(this);
        userLayout->addWidget(userEdit);
        authLayout->addLayout(userLayout);

        // Поле ввода пароля (скрытое)
        QHBoxLayout *passLayout = new QHBoxLayout();
        passLayout->addWidget(new QLabel("Пароль:"));
        passEdit = new QLineEdit(this);
        passEdit->setEchoMode(QLineEdit::Password);  // Скрываем вводимый текст
        passLayout->addWidget(passEdit);
        authLayout->addLayout(passLayout);

        mainLayout->addWidget(authGroup);

        //----------------------------------------------------------------------
        // Группа дополнительных настроек
        //----------------------------------------------------------------------
        QGroupBox *extraGroup = new QGroupBox("Дополнительно", this);
        QVBoxLayout *extraLayout = new QVBoxLayout(extraGroup);

        // Чекбокс автозагрузки
        autostartCheck = new QCheckBox("Запускать программу при старте Windows", this);
        autostartCheck->setChecked(AutostartManager::isInAutostart());
        extraLayout->addWidget(autostartCheck);

        mainLayout->addWidget(extraGroup);

        //----------------------------------------------------------------------
        // Кнопки управления диалогом
        //----------------------------------------------------------------------
        QHBoxLayout *btnLayout = new QHBoxLayout();
        QPushButton *saveBtn = new QPushButton("Сохранить", this);
        QPushButton *cancelBtn = new QPushButton("Отмена", this);

        saveBtn->setDefault(true);  // Кнопка по умолчанию (Enter)
        btnLayout->addStretch();
        btnLayout->addWidget(saveBtn);
        btnLayout->addWidget(cancelBtn);

        mainLayout->addLayout(btnLayout);

        //----------------------------------------------------------------------
        // Копирайт
        //----------------------------------------------------------------------
        QLabel *copyrightLabel = new QLabel("© 2026 POWer, Samara. Все права защищены.", this);
        copyrightLabel->setStyleSheet("color: gray; font-size: 9pt;");
        copyrightLabel->setAlignment(Qt::AlignCenter);
        mainLayout->addWidget(copyrightLabel);

        // Подключаем сигналы кнопок
        connect(saveBtn, &QPushButton::clicked, this, &QDialog::accept);
        connect(cancelBtn, &QPushButton::clicked, this, &QDialog::reject);

        // Загружаем ранее сохранённые настройки из реестра
        loadSettings();
    }

    //--------------------------------------------------------------------------
    // Геттеры для получения значений из полей ввода
    //--------------------------------------------------------------------------
    QString getHost() const { return hostEdit->text().trimmed(); }
    int getPort() const { return portSpin->value(); }
    QString getExceptions() const { return exceptionsEdit->text().trimmed(); }
    bool getBypassLocal() const { return bypassLocalCheck->isChecked(); }
    QString getUser() const { return userEdit->text().trimmed(); }
    QString getPassword() const { return passEdit->text(); }
    bool getAutostart() const { return autostartCheck->isChecked(); }

    //--------------------------------------------------------------------------
    // Сохранение настроек в реестр Windows
    // Путь: HKEY_CURRENT_USER\Software\ProxyMan
    //--------------------------------------------------------------------------
    void saveSettings() {
        QSettings settings("HKEY_CURRENT_USER\\Software\\ProxyMan", QSettings::NativeFormat);
        settings.setValue("ProxyServer", getHost());
        settings.setValue("ProxyPort", getPort());
        settings.setValue("ProxyExceptions", getExceptions());
        settings.setValue("ProxyBypassLocal", getBypassLocal());
        settings.setValue("ProxyUser", getUser());
        settings.setValue("ProxyPassword", getPassword());
        settings.sync();  // Принудительная запись в реестр

        // Управление автозагрузкой
        if (getAutostart()) {
            if (AutostartManager::addToAutostart()) {
                qDebug() << "Приложение добавлено в автозагрузку";
            }
        } else {
            if (AutostartManager::removeFromAutostart()) {
                qDebug() << "Приложение удалено из автозагрузки";
            }
        }
    }

    //--------------------------------------------------------------------------
    // Загрузка настроек из реестра Windows
    //--------------------------------------------------------------------------
    void loadSettings() {
        QSettings settings("HKEY_CURRENT_USER\\Software\\ProxyMan", QSettings::NativeFormat);
        hostEdit->setText(settings.value("ProxyServer", "").toString());
        portSpin->setValue(settings.value("ProxyPort", 8080).toInt());
        exceptionsEdit->setText(settings.value("ProxyExceptions", "localhost;127.0.0.1;*.local").toString());
        bypassLocalCheck->setChecked(settings.value("ProxyBypassLocal", true).toBool());
        userEdit->setText(settings.value("ProxyUser", "").toString());
        passEdit->setText(settings.value("ProxyPassword", "").toString());
        autostartCheck->setChecked(AutostartManager::isInAutostart());
    }

private:
    // Поля ввода диалога
    QLineEdit *hostEdit;
    QSpinBox *portSpin;
    QLineEdit *exceptionsEdit;
    QCheckBox *bypassLocalCheck;
    QLineEdit *userEdit;
    QLineEdit *passEdit;
    QCheckBox *autostartCheck;
};

//==============================================================================
// Класс для работы с системными настройками прокси Windows через WinInet API
//==============================================================================
class WindowsProxyManager {
public:
    //--------------------------------------------------------------------------
    // Установка системного прокси Windows
    // Параметры:
    //   server - адрес прокси-сервера
    //   port - порт прокси-сервера
    //   exceptions - список исключений (адреса без прокси)
    //   bypassLocal - флаг обхода прокси для локальных адресов
    //--------------------------------------------------------------------------
    static bool setSystemProxy(const QString &server, int port, const QString &exceptions, bool bypassLocal) {
#ifdef Q_OS_WIN
        // Формируем строку "адрес:порт"
        QString proxyServer = QString("%1:%2").arg(server).arg(port);

        // Структура для настройки параметров подключения
        INTERNET_PER_CONN_OPTION_LIST list;
        DWORD dwBufSize = sizeof(list);

        list.dwSize = sizeof(list);
        list.pszConnection = NULL;  // NULL = настройки по умолчанию для LAN
        list.dwOptionCount = 3;     // Количество опций для установки
        list.pOptions = new INTERNET_PER_CONN_OPTION[3];

        // Опция 1: Включаем прокси (разрешаем прямое и прокси-подключение)
        list.pOptions[0].dwOption = INTERNET_PER_CONN_FLAGS;
        list.pOptions[0].Value.dwValue = PROXY_TYPE_PROXY | PROXY_TYPE_DIRECT;

        // Опция 2: Устанавливаем адрес прокси-сервера
        list.pOptions[1].dwOption = INTERNET_PER_CONN_PROXY_SERVER;
        list.pOptions[1].Value.pszValue = _wcsdup(proxyServer.toStdWString().c_str());

        // Опция 3: Устанавливаем список исключений
        QString bypassList = exceptions;
        if (bypassLocal && !bypassList.isEmpty()) {
            bypassList += ";<local>";  // Добавляем <local> для локальных адресов
        } else if (bypassLocal) {
            bypassList = "<local>";
        }

        list.pOptions[2].dwOption = INTERNET_PER_CONN_PROXY_BYPASS;
        list.pOptions[2].Value.pszValue = _wcsdup(bypassList.toStdWString().c_str());

        // Применяем настройки через WinInet API
        BOOL bReturn = InternetSetOption(NULL, INTERNET_OPTION_PER_CONNECTION_OPTION, &list, dwBufSize);

        // Уведомляем систему об изменении настроек
        InternetSetOption(NULL, INTERNET_OPTION_SETTINGS_CHANGED, NULL, 0);
        InternetSetOption(NULL, INTERNET_OPTION_REFRESH, NULL, 0);

        // Освобождаем выделенную память
        free(list.pOptions[1].Value.pszValue);
        free(list.pOptions[2].Value.pszValue);
        delete[] list.pOptions;

        return bReturn;
#else
        return false;  // Только для Windows
#endif
    }

    //--------------------------------------------------------------------------
    // Отключение системного прокси Windows (прямое подключение)
    //--------------------------------------------------------------------------
    static bool disableSystemProxy() {
#ifdef Q_OS_WIN
        INTERNET_PER_CONN_OPTION_LIST list;
        DWORD dwBufSize = sizeof(list);

        list.dwSize = sizeof(list);
        list.pszConnection = NULL;
        list.dwOptionCount = 1;
        list.pOptions = new INTERNET_PER_CONN_OPTION[1];

        // Устанавливаем режим прямого подключения (без прокси)
        list.pOptions[0].dwOption = INTERNET_PER_CONN_FLAGS;
        list.pOptions[0].Value.dwValue = PROXY_TYPE_DIRECT;

        BOOL bReturn = InternetSetOption(NULL, INTERNET_OPTION_PER_CONNECTION_OPTION, &list, dwBufSize);

        // Применяем изменения
        InternetSetOption(NULL, INTERNET_OPTION_SETTINGS_CHANGED, NULL, 0);
        InternetSetOption(NULL, INTERNET_OPTION_REFRESH, NULL, 0);

        delete[] list.pOptions;
        return bReturn;
#else
        return false;
#endif
    }

    //--------------------------------------------------------------------------
    // Получение информации о текущих настройках системного прокси
    // Возвращает: строку с информацией о прокси или сообщение об ошибке
    //--------------------------------------------------------------------------
    static QString getSystemProxyInfo() {
#ifdef Q_OS_WIN
        INTERNET_PER_CONN_OPTION_LIST list;
        DWORD dwBufSize = sizeof(list);

        list.dwSize = sizeof(list);
        list.pszConnection = NULL;
        list.dwOptionCount = 3;
        list.pOptions = new INTERNET_PER_CONN_OPTION[3];

        // Запрашиваем: флаги, сервер и исключения
        list.pOptions[0].dwOption = INTERNET_PER_CONN_FLAGS;
        list.pOptions[1].dwOption = INTERNET_PER_CONN_PROXY_SERVER;
        list.pOptions[2].dwOption = INTERNET_PER_CONN_PROXY_BYPASS;

        if (InternetQueryOption(NULL, INTERNET_OPTION_PER_CONNECTION_OPTION, &list, &dwBufSize)) {
            QString info;

            // Проверяем, включён ли прокси
            if (list.pOptions[0].Value.dwValue & PROXY_TYPE_PROXY) {
                if (list.pOptions[1].Value.pszValue != NULL) {
                    info = QString("Прокси: %1").arg(QString::fromWCharArray(list.pOptions[1].Value.pszValue));
                    if (list.pOptions[2].Value.pszValue != NULL) {
                        info += QString("\nИсключения: %1").arg(QString::fromWCharArray(list.pOptions[2].Value.pszValue));
                    }
                    // Освобождаем память, выделенную Windows API
                    GlobalFree(list.pOptions[1].Value.pszValue);
                    if (list.pOptions[2].Value.pszValue) GlobalFree(list.pOptions[2].Value.pszValue);
                } else {
                    info = "Прокси включён (сервер не указан)";
                }
            } else {
                info = "Прокси отключён";
            }

            delete[] list.pOptions;
            return info;
        }

        delete[] list.pOptions;
        return "Не удалось получить информацию";
#else
        return "Только для Windows";
#endif
    }
};

//==============================================================================
// Главный класс приложения - управление системным треем и прокси
//==============================================================================
class TrayApp : public QObject {
    Q_OBJECT
public:
    // Конструктор приложения
    TrayApp(QObject *parent = nullptr) : QObject(parent) {
        // Загружаем последнее сохранённое состояние прокси из реестра
        QSettings settings("HKEY_CURRENT_USER\\Software\\ProxyMan", QSettings::NativeFormat);
        isProxyEnabled = settings.value("LastProxyState", false).toBool();

        // Создаём элементы интерфейса
        createTrayIcon();
        createMenu();

        // Устанавливаем контекстное меню для иконки в трее
        trayIcon->setContextMenu(trayMenu);
        trayIcon->show();

        // Qt будет использовать системные настройки прокси Windows
        QNetworkProxyFactory::setUseSystemConfiguration(true);

        // Обновляем внешний вид иконки в соответствии с состоянием
        updateTrayIcon();

        // Показываем приветственное сообщение
        trayIcon->showMessage("Прокси менеджер",
                             QString("Приложение запущено\nСостояние: %1\nЛКМ - переключение, ПКМ - меню\n\n© 2026 POWer, Samara")
                             .arg(isProxyEnabled ? "Прокси включён" : "Прямое подключение"),
                             QSystemTrayIcon::Information, 3000);
    }

private slots:
    //--------------------------------------------------------------------------
    // Переключение состояния прокси (вкл/выкл)
    // Вызывается при клике левой кнопкой мыши на иконке в трее
    //--------------------------------------------------------------------------
    void toggleProxy() {
        if (isProxyEnabled) {
            connectDirect();  // Если прокси включён - выключаем
        } else {
            connectWithSystemProxy();  // Если выключен - включаем
        }
    }

    //--------------------------------------------------------------------------
    // Включение прямого подключения (отключение прокси)
    //--------------------------------------------------------------------------
    void connectDirect() {
        // Пытаемся отключить системный прокси Windows
        if (WindowsProxyManager::disableSystemProxy()) {
            // Отключаем использование системных настроек в Qt
            QNetworkProxyFactory::setUseSystemConfiguration(false);
            QNetworkProxy::setApplicationProxy(QNetworkProxy::NoProxy);

            // Обновляем состояние
            isProxyEnabled = false;
            saveProxyState();  // Сохраняем в реестр
            updateTrayIcon();  // Перерисовываем иконку (красный цвет)

            // Уведомление пользователя
            trayIcon->showMessage("Прямое подключение",
                                 "Прокси отключён",
                                 QSystemTrayIcon::Information, 2000);
        } else {
            QMessageBox::warning(nullptr, "Ошибка",
                               "Не удалось отключить системный прокси");
        }
    }

    //--------------------------------------------------------------------------
    // Включение подключения через системный прокси
    //--------------------------------------------------------------------------
    void connectWithSystemProxy() {
        // Загружаем настройки прокси из реестра
        QSettings settings("HKEY_CURRENT_USER\\Software\\ProxyMan", QSettings::NativeFormat);
        QString host = settings.value("ProxyServer", "").toString();
        int port = settings.value("ProxyPort", 8080).toInt();
        QString exceptions = settings.value("ProxyExceptions", "localhost;127.0.0.1").toString();
        bool bypassLocal = settings.value("ProxyBypassLocal", true).toBool();

        // Проверяем, заданы ли настройки прокси
        if (host.isEmpty()) {
            QMessageBox::warning(nullptr, "Настройки не заданы",
                               "Адрес прокси сервера не задан!\n\nОткройте 'Настройки прокси' и укажите параметры подключения.");
            openProxySettings();  // Открываем диалог настроек
            return;
        }

        // Применяем настройки прокси к системе Windows
        if (WindowsProxyManager::setSystemProxy(host, port, exceptions, bypassLocal)) {
            // Qt будет использовать системные настройки
            QNetworkProxyFactory::setUseSystemConfiguration(true);

            // Обновляем состояние
            isProxyEnabled = true;
            saveProxyState();  // Сохраняем в реестр
            updateTrayIcon();  // Перерисовываем иконку (зелёный цвет)

            // Уведомление пользователя
            trayIcon->showMessage("Подключение через прокси",
                                 QString("Прокси включён: %1:%2").arg(host).arg(port),
                                 QSystemTrayIcon::Information, 2000);
        } else {
            QMessageBox::warning(nullptr, "Ошибка",
                               "Не удалось включить системный прокси");
        }
    }

    //--------------------------------------------------------------------------
    // Показать информацию о текущих настройках прокси
    //--------------------------------------------------------------------------
    void showProxyInfo() {
        // Получаем информацию о системных настройках Windows
        QString info = WindowsProxyManager::getSystemProxyInfo();
        QString status = isProxyEnabled ? "Включён" : "Отключён";

        // Получаем настройки из нашего приложения
        QSettings settings("HKEY_CURRENT_USER\\Software\\ProxyMan", QSettings::NativeFormat);
        QString savedHost = settings.value("ProxyServer", "не задан").toString();
        int savedPort = settings.value("ProxyPort", 8080).toInt();

        // Проверяем статус автозагрузки
        QString autostartStatus = AutostartManager::isInAutostart() ? "Да" : "Нет";

        // Показываем диалог с информацией
        QMessageBox msgBox;
        msgBox.setWindowTitle("Информация о прокси");
        msgBox.setText(QString("Статус приложения: %1\n\n"
                              "Системные настройки Windows:\n%2\n\n"
                              "Настройки приложения:\nСервер: %3\nПорт: %4\n\n"
                              "Автозагрузка: %5")
                      .arg(status).arg(info).arg(savedHost).arg(savedPort).arg(autostartStatus));

        // Добавляем копирайт в информационное окно
        msgBox.setInformativeText("© 2026 POWer, Samara");
        msgBox.setIcon(QMessageBox::Information);
        msgBox.exec();
    }

    //--------------------------------------------------------------------------
    // Открыть диалог настроек прокси приложения
    //--------------------------------------------------------------------------
    void openProxySettings() {
        ProxySettingsDialog dialog;
        if (dialog.exec() == QDialog::Accepted) {
            // Пользователь нажал "Сохранить"
            dialog.saveSettings();
            QMessageBox::information(nullptr, "Настройки сохранены",
                                   QString("Настройки прокси сохранены:\n%1:%2\n\n"
                                          "Для применения включите прокси через меню или ЛКМ.")
                                   .arg(dialog.getHost()).arg(dialog.getPort()));
        }
    }

    //--------------------------------------------------------------------------
    // Открыть системные настройки прокси Windows
    //--------------------------------------------------------------------------
    void openWindowsProxySettings() {
#ifdef Q_OS_WIN
        // Открываем стандартные настройки Windows через URI
        system("start ms-settings:network-proxy");
#endif
    }

    //--------------------------------------------------------------------------
    // Показать окно "О программе"
    //--------------------------------------------------------------------------
    void showAbout() {
        QMessageBox aboutBox;
        aboutBox.setWindowTitle("О программе");
        aboutBox.setTextFormat(Qt::RichText);
        aboutBox.setText(
            "<h2>Прокси Менеджер</h2>"
            "<p><b>Версия:</b> 1.0</p>"
            "<p><b>Дата выпуска:</b> 2026</p>"
            "<p>Программа для быстрого управления системным прокси Windows</p>"
        );
        aboutBox.setInformativeText(
            "<p><b>Возможности:</b></p>"
            "<ul>"
            "<li>Быстрое переключение прокси одним кликом</li>"
            "<li>Настройка параметров прокси-сервера</li>"
            "<li>Управление исключениями</li>"
            "<li>Автозагрузка с Windows</li>"
            "<li>Работа в системном трее</li>"
            "</ul>"
            "<br>"
            "<p align='center'><b>© 2026 POWer, Samara</b><br>"
            "Все права защищены</p>"
        );

        // Загружаем и устанавливаем иконку приложения
        QPixmap iconPixmap(":/ProxyMan.ico");
        if (!iconPixmap.isNull()) {
            // Масштабируем иконку до подходящего размера (64x64)
            aboutBox.setIconPixmap(iconPixmap.scaled(128, 128, Qt::KeepAspectRatio, Qt::SmoothTransformation));
        } else {
            // Если файл не найден, используем стандартную иконку
            aboutBox.setIcon(QMessageBox::Information);
        }

        aboutBox.setStandardButtons(QMessageBox::Ok);
        aboutBox.exec();
    }

    //--------------------------------------------------------------------------
    // Закрыть приложение
    //--------------------------------------------------------------------------
    void quitApp() {
        QApplication::quit();
    }

private:
    //--------------------------------------------------------------------------
    // Создание иконки системного трея
    //--------------------------------------------------------------------------
    void createTrayIcon() {
        trayIcon = new QSystemTrayIcon(this);
        // Подключаем обработчик кликов по иконке
        connect(trayIcon, &QSystemTrayIcon::activated, this, &TrayApp::iconActivated);
    }

    //--------------------------------------------------------------------------
    // Создание контекстного меню (ПКМ по иконке)
    //--------------------------------------------------------------------------
    void createMenu() {
        trayMenu = new QMenu();

        // Действие: быстрое переключение прокси
        QAction *toggleAction = new QAction("🔄 Переключить прокси", this);
        connect(toggleAction, &QAction::triggered, this, &TrayApp::toggleProxy);

        trayMenu->addAction(toggleAction);
        trayMenu->addSeparator();

        // Действие: включить прямое подключение
        QAction *directAction = new QAction("🔴 Прямое подключение", this);
        connect(directAction, &QAction::triggered, this, &TrayApp::connectDirect);

        // Действие: включить прокси
        QAction *proxyAction = new QAction("🟢 Включить прокси", this);
        connect(proxyAction, &QAction::triggered, this, &TrayApp::connectWithSystemProxy);

        trayMenu->addAction(directAction);
        trayMenu->addAction(proxyAction);
        trayMenu->addSeparator();

        // Действие: открыть настройки прокси
        QAction *settingsAction = new QAction("⚙️ Настройки прокси...", this);
        connect(settingsAction, &QAction::triggered, this, &TrayApp::openProxySettings);

        // Действие: показать информацию
        QAction *infoAction = new QAction("ℹ️ Информация", this);
        connect(infoAction, &QAction::triggered, this, &TrayApp::showProxyInfo);

        QAction *aboutAction = new QAction("📄 О программе", this);
        connect(aboutAction, &QAction::triggered, this, &TrayApp::showAbout);

        trayMenu->addAction(settingsAction);
        trayMenu->addAction(infoAction);
        trayMenu->addAction(aboutAction);
        trayMenu->addSeparator();

        // Действие: выход из приложения
        QAction *quitAction = new QAction("❌ Выход", this);
        connect(quitAction, &QAction::triggered, this, &TrayApp::quitApp);

        trayMenu->addAction(quitAction);
    }

    //--------------------------------------------------------------------------
    // Обновление внешнего вида иконки в трее
    // Цвет зависит от состояния: зелёный = прокси включён, красный = выключен
    //--------------------------------------------------------------------------
    void updateTrayIcon() {
        // Создаём пустое изображение 64x64 пикселя
        QPixmap pixmap(64, 64);
        pixmap.fill(Qt::transparent);  // Прозрачный фон

        QPainter painter(&pixmap);
        painter.setRenderHint(QPainter::Antialiasing);  // Сглаживание

        // Выбираем цвет в зависимости от состояния прокси
        QColor color = isProxyEnabled ? QColor(0, 200, 0) : QColor(200, 50, 50);

        // Рисуем круг
        painter.setBrush(QBrush(color));  // Заливка цветом
        painter.setPen(QPen(color.darker(120), 3));  // Обводка (темнее на 20%)
        painter.drawEllipse(6, 6, 52, 52);  // Круг с небольшим отступом

        // Рисуем букву "P" в центре круга
        painter.setPen(QPen(Qt::white, 4));  // Белый цвет текста
        painter.setFont(QFont("Arial", 28, QFont::Bold));  // Жирный шрифт
        painter.drawText(pixmap.rect(), Qt::AlignCenter, "P");

        // Устанавливаем иконку в трей
        trayIcon->setIcon(QIcon(pixmap));

        // Устанавливаем всплывающую подсказку
        QString tooltip = isProxyEnabled ?
            "Прокси менеджер: Прокси включён (ЛКМ - выключить)" :
            "Прокси менеджер: Прямое подключение (ЛКМ - включить прокси)";
        trayIcon->setToolTip(tooltip);
    }

    //--------------------------------------------------------------------------
    // Обработчик событий клика по иконке в трее
    //--------------------------------------------------------------------------
    void iconActivated(QSystemTrayIcon::ActivationReason reason) {
        if (reason == QSystemTrayIcon::Trigger) {
            // Триггер = левая кнопка мыши (одинарный клик)
            toggleProxy();  // Переключаем состояние прокси
        }
        // ПКМ обрабатывается автоматически (открывается contextMenu)
    }

    //--------------------------------------------------------------------------
    // Сохранение текущего состояния прокси в реестр
    // Это позволяет восстановить состояние при следующем запуске программы
    //--------------------------------------------------------------------------
    void saveProxyState() {
        QSettings settings("HKEY_CURRENT_USER\\Software\\ProxyMan", QSettings::NativeFormat);
        settings.setValue("LastProxyState", isProxyEnabled);
        settings.sync();  // Принудительная запись в реестр
    }

    // Члены класса
    QSystemTrayIcon *trayIcon;  // Иконка в системном трее
    QMenu *trayMenu;            // Контекстное меню
    bool isProxyEnabled;        // Флаг состояния прокси (вкл/выкл)
};

//==============================================================================
// Точка входа в программу
//==============================================================================
int main(int argc, char *argv[]) {
    QApplication app(argc, argv);

    //--------------------------------------------------------------------------
    // Проверка на единственный экземпляр приложения
    //--------------------------------------------------------------------------
    SingleInstanceGuard instanceGuard("ProxyMan_SingleInstance_A7F3E9B2");

    if (instanceGuard.isAnotherRunning()) {
        QMessageBox::warning(
            nullptr,
            "Приложение уже запущено",
            "Прокси Менеджер уже запущен!\n\n"
            "Проверьте системный трей (область уведомлений).\n"
            "Для выхода из работающего приложения используйте ПКМ → Выход.\n\n"
            "© 2026 POWer, Samara"
        );
        return 0;  // Выходим, не запуская второй экземпляр
    }

    // Проверяем доступность системного трея
    if (!QSystemTrayIcon::isSystemTrayAvailable()) {
        QMessageBox::critical(nullptr, "Ошибка",
                            "Системный трей недоступен в вашей системе!");
        return 1;
    }

    // Не закрываем приложение при закрытии всех окон
    // (программа работает в фоне через системный трей)
    QApplication::setQuitOnLastWindowClosed(false);

    // Создаём главный объект приложения
    TrayApp trayApp;

    // Запускаем цикл обработки событий Qt
    return app.exec();
}

// Включаем moc (Meta-Object Compiler) для обработки Q_OBJECT макросов
#include "main.moc"
