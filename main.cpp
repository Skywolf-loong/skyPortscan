#include <Windows.h>
#include <QApplication>
#include <QMainWindow>
#include <QLineEdit>
#include <QPushButton>
#include <QTableWidget>
#include <QHeaderView>
#include <QStatusBar>
#include <QThread>
#include <QTcpSocket>
#include <QRegularExpression>
#include <QNetworkAccessManager>
#include <QNetworkReply>
#include <QMessageBox>
#include <QUrl>
#include <QTimer>
#include <QEventLoop>
#include <QVBoxLayout>
#include <QHBoxLayout>
#include <QLabel>
#include <QProgressBar>
#include <QThreadPool>
#include <QRunnable>
#include <QSet>
#include <QProcess>
#include <QCoreApplication>
#include <QHostInfo>
#include <QFileDialog>
#include <QSettings>
#include <QDialog>
#include <QFormLayout>
#include <QSpinBox>
#include <QComboBox>
#include <QPlainTextEdit>
#include <QStringDecoder>
#include <QChartView>
#include <QPieSeries>
#include <QChart>
#include <QFile>
#include <QDateTime>
#include <QJsonDocument>
#include <QJsonObject>
#include <QJsonArray>
#include <QNetworkProxy>
#include <QInputDialog>
#include <QTabWidget>
#include <QGroupBox>
#include <QToolBar>
#include <QAction>
#include <QMenu>
#include <QMenuBar>
#include <QFileInfo>
#include <QDesktopServices>
#include <QClipboard>
#include <QStandardPaths>
#include <QGuiApplication>
#include <QScreen>
#include <QSizePolicy>
#include <QDesktopServices>
#include <QDir>

// ============================
// 服务识别模块
// ============================
class ServiceRecognizer : public QObject {
    Q_OBJECT
public:
    ServiceRecognizer(QObject *parent = nullptr) : QObject(parent) {
        loadServiceDefinitions();
    }

    struct ServiceInfo {
        QString name;
        QString displayName;
        QRegularExpression bannerRegex;
        QString versionPattern;
        QList<int> possiblePorts;
        QString category;
    };

    QMap<QString, ServiceInfo> recognize(int port, const QString &banner) {
        QMap<QString, ServiceInfo> results;

        // 1. 端口匹配
        for (const auto &service : serviceDefinitions) {
            if (service.possiblePorts.contains(port)) {
                results[service.name] = service;
            }
        }

        // 2. Banner匹配
        for (const auto &service : serviceDefinitions) {
            if (!service.bannerRegex.pattern().isEmpty()) {
                QRegularExpressionMatch match = service.bannerRegex.match(banner);
                if (match.hasMatch()) {
                    results[service.name] = service;

                    // 提取版本信息
                    if (!service.versionPattern.isEmpty()) {
                        ServiceInfo versionInfo = service;
                        versionInfo.versionPattern = match.captured(1);
                        results[service.name + "_version"] = versionInfo;
                    }
                }
            }
        }

        // 3. 特殊服务识别
        if (banner.contains("SSH", Qt::CaseInsensitive)) {
            results["ssh"] = serviceDefinitions["ssh"];
        }

        return results;
    }

    QString detectWebFramework(const QString &headers, const QString &htmlContent) {
        // 1. HTTP头识别
        for (const auto &service : serviceDefinitions) {
            if (service.category == "web" && !service.bannerRegex.pattern().isEmpty()) {
                if (headers.contains(service.bannerRegex)) {
                    return service.displayName;
                }
            }
        }

        // 2. HTML内容识别
        for (const auto &service : serviceDefinitions) {
            if (service.category == "web" && !service.versionPattern.isEmpty()) {
                QRegularExpression re(service.versionPattern);
                if (re.match(htmlContent).hasMatch()) {
                    return service.displayName;
                }
            }
        }

        // 3. URL路径识别
        if (htmlContent.contains("wp-content") || htmlContent.contains("wp-admin")) {
            return "WordPress";
        }

        if (htmlContent.contains("/static/admin/")) {
            return "Django";
        }

        return "";
    }

private:
    void loadServiceDefinitions() {
        // 从JSON文件加载服务定义
        QFile file("services.json");
        if (file.open(QIODevice::ReadOnly)) {
            QJsonDocument doc = QJsonDocument::fromJson(file.readAll());
            QJsonArray services = doc.array();

            for (const QJsonValue &serviceVal : services) {
                QJsonObject serviceObj = serviceVal.toObject();
                ServiceInfo info;
                info.name = serviceObj["name"].toString();
                info.displayName = serviceObj["displayName"].toString();
                info.bannerRegex = QRegularExpression(serviceObj["bannerRegex"].toString());
                info.versionPattern = serviceObj["versionPattern"].toString();
                info.category = serviceObj["category"].toString();

                QJsonArray ports = serviceObj["ports"].toArray();
                for (const QJsonValue &portVal : ports) {
                    info.possiblePorts.append(portVal.toInt());
                }

                serviceDefinitions[info.name] = info;
            }
        } else {
            // 内置默认服务定义
            loadDefaultServices();
        }
    }

    void loadDefaultServices() {
        // HTTP
        ServiceInfo http;
        http.name = "http";
        http.displayName = "HTTP Server";
        http.bannerRegex = QRegularExpression("HTTP/\\d\\.\\d");
        http.versionPattern = "Server: ([^\\s]+)";
        http.possiblePorts = {80, 8080, 8000, 8888};
        http.category = "web";
        serviceDefinitions["http"] = http;

        // SSH
        ServiceInfo ssh;
        ssh.name = "ssh";
        ssh.displayName = "SSH";
        ssh.bannerRegex = QRegularExpression("SSH-\\d\\.\\d-OpenSSH_(\\d+\\.\\d+)");
        ssh.possiblePorts = {22};
        ssh.category = "remote";
        serviceDefinitions["ssh"] = ssh;

        // FTP
        ServiceInfo ftp;
        ftp.name = "ftp";
        ftp.displayName = "FTP";
        ftp.bannerRegex = QRegularExpression("220 ([^\\s]+) FTP server");
        ftp.possiblePorts = {21};
        ftp.category = "file";
        serviceDefinitions["ftp"] = ftp;

        // MySQL
        ServiceInfo mysql;
        mysql.name = "mysql";
        mysql.displayName = "MySQL";
        mysql.bannerRegex = QRegularExpression("\\d+\\.\\d+\\.\\d+\\-MySQL");
        mysql.possiblePorts = {3306};
        mysql.category = "database";
        serviceDefinitions["mysql"] = mysql;

        // Telnet (远程登录)
        ServiceInfo telnet;
        telnet.name = "telnet";
        telnet.displayName = "Telnet";
        telnet.bannerRegex = QRegularExpression("Telnet");
        telnet.possiblePorts = {23};
        telnet.category = "remote";
        serviceDefinitions["telnet"] = telnet;

        // RDP (远程桌面协议)
        ServiceInfo rdp;
        rdp.name = "rdp";
        rdp.displayName = "RDP";
        rdp.bannerRegex = QRegularExpression("Microsoft Terminal Services");
        rdp.possiblePorts = {3389};
        rdp.category = "remote";
        serviceDefinitions["rdp"] = rdp;

        // SMB/NetBIOS (文件共享)
        ServiceInfo smb;
        smb.name = "smb";
        smb.displayName = "SMB";
        smb.bannerRegex = QRegularExpression("SMB");
        smb.possiblePorts = {135, 137, 138, 139, 445};
        smb.category = "file";
        serviceDefinitions["smb"] = smb;

        // LDAP (目录服务)
        ServiceInfo ldap;
        ldap.name = "ldap";
        ldap.displayName = "LDAP";
        ldap.bannerRegex = QRegularExpression("LDAP");
        ldap.possiblePorts = {389};
        ldap.category = "directory";
        serviceDefinitions["ldap"] = ldap;

        // SQL Server
        ServiceInfo sqlserver;
        sqlserver.name = "sqlserver";
        sqlserver.displayName = "SQL Server";
        sqlserver.bannerRegex = QRegularExpression("SQL Server");
        sqlserver.possiblePorts = {1433};
        sqlserver.category = "database";
        serviceDefinitions["sqlserver"] = sqlserver;

        // PostgreSQL
        ServiceInfo postgresql;
        postgresql.name = "postgresql";
        postgresql.displayName = "PostgreSQL";
        postgresql.bannerRegex = QRegularExpression("PostgreSQL");
        postgresql.possiblePorts = {5432};
        postgresql.category = "database";
        serviceDefinitions["postgresql"] = postgresql;

        // Oracle DB
        ServiceInfo oracle;
        oracle.name = "oracle";
        oracle.displayName = "Oracle DB";
        oracle.bannerRegex = QRegularExpression("Oracle");
        oracle.possiblePorts = {1521};
        oracle.category = "database";
        serviceDefinitions["oracle"] = oracle;

        // VNC (远程控制)
        ServiceInfo vnc;
        vnc.name = "vnc";
        vnc.displayName = "VNC";
        vnc.bannerRegex = QRegularExpression("RFB");
        vnc.possiblePorts = {5900, 5901, 5902};
        vnc.category = "remote";
        serviceDefinitions["vnc"] = vnc;

        // Redis (内存数据库)
        ServiceInfo redis;
        redis.name = "redis";
        redis.displayName = "Redis";
        redis.bannerRegex = QRegularExpression("Redis");
        redis.possiblePorts = {6379};
        redis.category = "database";
        serviceDefinitions["redis"] = redis;

        // Elasticsearch
        ServiceInfo elasticsearch;
        elasticsearch.name = "elasticsearch";
        elasticsearch.displayName = "Elasticsearch";
        elasticsearch.bannerRegex = QRegularExpression("Elasticsearch");
        elasticsearch.possiblePorts = {9200, 9300};
        elasticsearch.category = "database";
        serviceDefinitions["elasticsearch"] = elasticsearch;

        // Memcached
        ServiceInfo memcached;
        memcached.name = "memcached";
        memcached.displayName = "Memcached";
        memcached.bannerRegex = QRegularExpression("Memcached");
        memcached.possiblePorts = {11211};
        memcached.category = "cache";
        serviceDefinitions["memcached"] = memcached;

        // MongoDB
        ServiceInfo mongodb;
        mongodb.name = "mongodb";
        mongodb.displayName = "MongoDB";
        mongodb.bannerRegex = QRegularExpression("MongoDB");
        mongodb.possiblePorts = {27017, 27018};
        mongodb.category = "database";
        serviceDefinitions["mongodb"] = mongodb;
    }

    QMap<QString, ServiceInfo> serviceDefinitions;
};

// ============================
// 扫描设置类
// ============================
class ScannerSettings : public QObject {
    Q_OBJECT
public:
    enum ScanMode {
        TCP_CONNECT,
        SYN_SCAN
    };

    ScannerSettings(QObject *parent = nullptr) : QObject(parent) {
        load();
    }

    void save() {
        QSettings settings("PortScanner", "Settings");

        QJsonObject config;
        config["userAgent"] = userAgent;
        config["threadCount"] = threadCount;
        config["connectTimeout"] = connectTimeout;
        config["readTimeout"] = readTimeout;
        config["httpTimeout"] = httpTimeout;
        config["scanMode"] = static_cast<int>(scanMode);
        config["proxyType"] = static_cast<int>(proxy.type());
        config["proxyHost"] = proxy.hostName();
        config["proxyPort"] = proxy.port();
        config["proxyUser"] = proxy.user();
        config["proxyPassword"] = proxy.password();

        settings.setValue("config", QJsonDocument(config).toJson());
    }

    void load() {
        QSettings settings("PortScanner", "Settings");
        QByteArray configData = settings.value("config").toByteArray();

        if (!configData.isEmpty()) {
            QJsonDocument doc = QJsonDocument::fromJson(configData);
            QJsonObject config = doc.object();

            userAgent = config["userAgent"].toString("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36");
            threadCount = config["threadCount"].toInt(50);
            connectTimeout = config["connectTimeout"].toInt(500);
            readTimeout = config["readTimeout"].toInt(1000);
            httpTimeout = config["httpTimeout"].toInt(3000);
            scanMode = static_cast<ScanMode>(config["scanMode"].toInt(0));

            proxy.setType(static_cast<QNetworkProxy::ProxyType>(config["proxyType"].toInt(0)));
            proxy.setHostName(config["proxyHost"].toString());
            proxy.setPort(config["proxyPort"].toInt(8080));
            proxy.setUser(config["proxyUser"].toString());
            proxy.setPassword(config["proxyPassword"].toString());
        } else {
            // 默认设置
            userAgent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36";
            threadCount = 50;
            connectTimeout = 500;
            readTimeout = 1000;
            httpTimeout = 3000;
            scanMode = TCP_CONNECT;
            proxy.setType(QNetworkProxy::NoProxy);
        }
    }

    QVariant value(const QString &key, const QVariant &defaultValue = QVariant()) const {
        QSettings settings("PortScanner", "Settings");
        return settings.value(key, defaultValue);
    }

    // 添加设置值方法
    void setValue(const QString &key, const QVariant &value) {
        QSettings settings("PortScanner", "Settings");
        settings.setValue(key, value);
    }

    QString userAgent;
    int threadCount;
    int connectTimeout;
    int readTimeout;
    int httpTimeout;
    ScanMode scanMode;
    QNetworkProxy proxy;
};

// ============================
// 扫描任务类
// ============================
class ScanTask : public QRunnable {
public:
    ScanTask(const QString &target, int port, ScannerSettings *settings,
             ServiceRecognizer *recognizer, QObject *receiver)
        : m_target(target), m_port(port), m_settings(settings),
        m_recognizer(recognizer), m_receiver(receiver) {}

    void run() override {
        // TCP连接扫描
        QTcpSocket socket;

        // 应用代理设置
        if (m_settings->proxy.type() != QNetworkProxy::NoProxy) {
            socket.setProxy(m_settings->proxy);
        }

        socket.connectToHost(m_target, m_port);

        if (socket.waitForConnected(m_settings->connectTimeout)) {
            QString banner = "";
            QString serviceInfo = "";
            QString version = "";
            QString category = "";

            // 尝试读取banner
            if (socket.waitForReadyRead(m_settings->readTimeout)) {
                banner = socket.read(1024).trimmed();

                // 服务识别
                auto services = m_recognizer->recognize(m_port, banner);
                if (!services.isEmpty()) {
                    const auto &primaryService = services.first();
                    serviceInfo = primaryService.displayName;
                    category = primaryService.category;

                    // 提取版本信息
                    if (!primaryService.versionPattern.isEmpty()) {
                        version = primaryService.versionPattern;
                    }
                }

                // 特殊服务处理
                if (serviceInfo == "FTP") {
                    banner = tryFTPAnonymous(socket, banner);
                }
            }

            QString title = "";
            QString webFramework = "";
            if (category == "web") {
                title = fetchHttpTitle(m_port);
            }

            QMetaObject::invokeMethod(m_receiver, "portFound",
                                      Q_ARG(int, m_port),
                                      Q_ARG(QString, serviceInfo),
                                      Q_ARG(QString, version),
                                      Q_ARG(QString, title),
                                      Q_ARG(QString, webFramework),
                                      Q_ARG(QString, category),
                                      Q_ARG(QString, banner));

            socket.disconnectFromHost();
        }

        // 通知任务完成
        QMetaObject::invokeMethod(m_receiver, "taskCompleted");
    }

private:
    QString tryFTPAnonymous(QTcpSocket &socket, const QString &initialBanner) {
        QString response = initialBanner;

        // 尝试匿名登录
        socket.write("USER anonymous\r\n");
        if (socket.waitForBytesWritten(1000)) {
            if (socket.waitForReadyRead(1000)) {
                response += "\n" + socket.readAll().trimmed();

                socket.write("PASS anonymous@example.com\r\n");
                if (socket.waitForBytesWritten(1000)) {
                    if (socket.waitForReadyRead(1000)) {
                        response += "\n" + socket.readAll().trimmed();

                        // 尝试获取目录列表
                        socket.write("PWD\r\n");
                        socket.waitForBytesWritten(1000);
                        socket.waitForReadyRead(1000);
                        response += "\n" + socket.readAll().trimmed();
                    }
                }
            }
        }

        return response;
    }

    QString fetchHttpTitle(int port) {
        QString protocol = (port == 443) ? "https" : "http";
        QUrl url(protocol + "://" + m_target + ":" + QString::number(port));
        QEventLoop loop;
        QString title = "";

        QNetworkAccessManager manager;

        // 应用代理设置
        if (m_settings->proxy.type() != QNetworkProxy::NoProxy) {
            manager.setProxy(m_settings->proxy);
        }

        QNetworkRequest request(url);
        request.setRawHeader("User-Agent", m_settings->userAgent.toUtf8());
        manager.setRedirectPolicy(QNetworkRequest::NoLessSafeRedirectPolicy);

        // 设置超时定时器
        QTimer timer;
        timer.setSingleShot(true);
        timer.start(m_settings->httpTimeout);

        QNetworkReply *reply = manager.get(request);

        // 连接超时信号
        QObject::connect(&timer, &QTimer::timeout, [&]() {
            reply->abort();
            loop.quit();
        });

        // 连接完成信号
        QObject::connect(reply, &QNetworkReply::finished, [&]() {
            if (reply->error() == QNetworkReply::NoError) {
                // 获取响应内容
                QByteArray data = reply->readAll();

                // 尝试检测编码
                QString encoding = "UTF-8";
                QString contentType = reply->header(QNetworkRequest::ContentTypeHeader).toString();
                QRegularExpression re("charset=([^;\\s]*)", QRegularExpression::CaseInsensitiveOption);
                QRegularExpressionMatch match = re.match(contentType);
                if (match.hasMatch()) {
                    encoding = match.captured(1);
                }

                // 使用QStringDecoder转换编码
                QStringDecoder decoder(encoding.toUtf8());
                if (!decoder.isValid()) {
                    decoder = QStringDecoder(QStringDecoder::Utf8);
                }
                QString html = decoder.decode(data);

                // 提取标题
                QRegularExpression titleRe("<title>(.*?)</title>",
                                           QRegularExpression::CaseInsensitiveOption |
                                               QRegularExpression::DotMatchesEverythingOption);
                QRegularExpressionMatch titleMatch = titleRe.match(html);

                if (titleMatch.hasMatch()) {
                    title = titleMatch.captured(1).left(100);
                    title = title.replace('\n', ' ').replace('\r', ' ').simplified();
                }
            }
            loop.quit();
        });

        loop.exec();
        reply->deleteLater();
        return title;
    }

    QString m_target;
    int m_port;
    ScannerSettings *m_settings;
    ServiceRecognizer *m_recognizer;
    QObject *m_receiver;
};

// ============================
// 设置对话框
// ============================
class SettingsDialog : public QDialog {
    Q_OBJECT
public:
    SettingsDialog(ScannerSettings *settings, QWidget *parent = nullptr)
        : QDialog(parent), m_settings(settings) {
        setWindowTitle("扫描设置");
        setFixedSize(600, 450);

        QTabWidget *tabWidget = new QTabWidget(this);
        QVBoxLayout *layout = new QVBoxLayout(this);
        layout->addWidget(tabWidget);

        // 常规设置标签页
        QWidget *generalTab = new QWidget;
        QFormLayout *generalLayout = new QFormLayout(generalTab);

        // User-Agent
        userAgentEdit = new QLineEdit(m_settings->userAgent, this);
        generalLayout->addRow("User-Agent:", userAgentEdit);

        // 线程数
        threadCountSpin = new QSpinBox(this);
        threadCountSpin->setRange(1, 500);
        threadCountSpin->setValue(m_settings->threadCount);
        generalLayout->addRow("线程数:", threadCountSpin);

        // 扫描模式
        scanModeCombo = new QComboBox(this);
        scanModeCombo->addItem("TCP连接扫描", ScannerSettings::TCP_CONNECT);
        scanModeCombo->addItem("SYN扫描(需要管理员权限)", ScannerSettings::SYN_SCAN);
        scanModeCombo->setCurrentIndex(static_cast<int>(m_settings->scanMode));
        generalLayout->addRow("扫描模式:", scanModeCombo);

        // 连接超时
        connectTimeoutSpin = new QSpinBox(this);
        connectTimeoutSpin->setRange(100, 10000);
        connectTimeoutSpin->setValue(m_settings->connectTimeout);
        connectTimeoutSpin->setSuffix(" ms");
        generalLayout->addRow("连接超时:", connectTimeoutSpin);

        // 读取超时
        readTimeoutSpin = new QSpinBox(this);
        readTimeoutSpin->setRange(100, 10000);
        readTimeoutSpin->setValue(m_settings->readTimeout);
        readTimeoutSpin->setSuffix(" ms");
        generalLayout->addRow("读取超时:", readTimeoutSpin);

        // HTTP超时
        httpTimeoutSpin = new QSpinBox(this);
        httpTimeoutSpin->setRange(1000, 10000);
        httpTimeoutSpin->setValue(m_settings->httpTimeout);
        httpTimeoutSpin->setSuffix(" ms");
        generalLayout->addRow("HTTP超时:", httpTimeoutSpin);

        tabWidget->addTab(generalTab, "常规");

        // 代理设置标签页
        QWidget *proxyTab = new QWidget;
        QFormLayout *proxyLayout = new QFormLayout(proxyTab);

        // 代理类型
        proxyTypeCombo = new QComboBox(this);
        proxyTypeCombo->addItem("无代理", QNetworkProxy::NoProxy);
        proxyTypeCombo->addItem("HTTP代理", QNetworkProxy::HttpProxy);
        proxyTypeCombo->addItem("SOCKS5代理", QNetworkProxy::Socks5Proxy);

        for (int i = 0; i < proxyTypeCombo->count(); i++) {
            if (proxyTypeCombo->itemData(i).toInt() == static_cast<int>(m_settings->proxy.type())) {
                proxyTypeCombo->setCurrentIndex(i);
                break;
            }
        }

        proxyLayout->addRow("代理类型:", proxyTypeCombo);

        // 代理主机
        proxyHostEdit = new QLineEdit(m_settings->proxy.hostName(), this);
        proxyLayout->addRow("代理主机:", proxyHostEdit);

        // 代理端口
        proxyPortSpin = new QSpinBox(this);
        proxyPortSpin->setRange(1, 65535);
        proxyPortSpin->setValue(m_settings->proxy.port());
        proxyLayout->addRow("代理端口:", proxyPortSpin);

        // 代理用户名
        proxyUserEdit = new QLineEdit(m_settings->proxy.user(), this);
        proxyLayout->addRow("用户名:", proxyUserEdit);

        // 代理密码
        proxyPassEdit = new QLineEdit(m_settings->proxy.password(), this);
        proxyPassEdit->setEchoMode(QLineEdit::Password);
        proxyLayout->addRow("密码:", proxyPassEdit);

        tabWidget->addTab(proxyTab, "代理");

        // 按钮
        QHBoxLayout *buttonLayout = new QHBoxLayout();
        QPushButton *saveButton = new QPushButton("保存", this);
        QPushButton *cancelButton = new QPushButton("取消", this);
        buttonLayout->addWidget(saveButton);
        buttonLayout->addWidget(cancelButton);

        layout->addLayout(buttonLayout);

        connect(saveButton, &QPushButton::clicked, this, &SettingsDialog::saveSettings);
        connect(cancelButton, &QPushButton::clicked, this, &SettingsDialog::reject);
    }

private slots:
    void saveSettings() {
        m_settings->userAgent = userAgentEdit->text();
        m_settings->threadCount = threadCountSpin->value();
        m_settings->scanMode = static_cast<ScannerSettings::ScanMode>(
            scanModeCombo->currentData().toInt());
        m_settings->connectTimeout = connectTimeoutSpin->value();
        m_settings->readTimeout = readTimeoutSpin->value();
        m_settings->httpTimeout = httpTimeoutSpin->value();

        m_settings->proxy.setType(static_cast<QNetworkProxy::ProxyType>(
            proxyTypeCombo->currentData().toInt()));
        m_settings->proxy.setHostName(proxyHostEdit->text());
        m_settings->proxy.setPort(proxyPortSpin->value());
        m_settings->proxy.setUser(proxyUserEdit->text());
        m_settings->proxy.setPassword(proxyPassEdit->text());

        m_settings->save();
        accept();
    }

private:
    ScannerSettings *m_settings;

    // 常规设置控件
    QLineEdit *userAgentEdit;
    QSpinBox *threadCountSpin;
    QComboBox *scanModeCombo;
    QSpinBox *connectTimeoutSpin;
    QSpinBox *readTimeoutSpin;
    QSpinBox *httpTimeoutSpin;

    // 代理设置控件
    QComboBox *proxyTypeCombo;
    QLineEdit *proxyHostEdit;
    QSpinBox *proxyPortSpin;
    QLineEdit *proxyUserEdit;
    QLineEdit *proxyPassEdit;
};

// ============================
// 端口详情对话框
// ============================
class PortDetailsDialog : public QDialog {
    Q_OBJECT
public:
    PortDetailsDialog(int port, const QString &service, const QString &version,
                      const QString &title, const QString &framework,
                      const QString &category, const QString &banner,
                      QWidget *parent = nullptr)
        : QDialog(parent) {
        setWindowTitle(QString("端口 %1 详情").arg(port));
        setMinimumSize(500, 400);

        QFormLayout *layout = new QFormLayout(this);

        layout->addRow("端口:", new QLabel(QString::number(port)));
        layout->addRow("服务:", new QLabel(service));

        if (!version.isEmpty()) {
            layout->addRow("版本:", new QLabel(version));
        }

        if (!title.isEmpty()) {
            layout->addRow("网页标题:", new QLabel(title));
        }

        if (!framework.isEmpty()) {
            layout->addRow("Web框架:", new QLabel(framework));
        }

        layout->addRow("类别:", new QLabel(category));

        // Banner显示
        QGroupBox *bannerGroup = new QGroupBox("Banner信息", this);
        QVBoxLayout *bannerLayout = new QVBoxLayout(bannerGroup);
        QPlainTextEdit *bannerEdit = new QPlainTextEdit(banner, this);
        bannerEdit->setReadOnly(true);
        bannerEdit->setWordWrapMode(QTextOption::NoWrap);
        bannerLayout->addWidget(bannerEdit);
        layout->addRow(bannerGroup);

        // 按钮
        QHBoxLayout *buttonLayout = new QHBoxLayout();
        QPushButton *copyButton = new QPushButton("复制Banner", this);
        QPushButton *closeButton = new QPushButton("关闭", this);
        buttonLayout->addWidget(copyButton);
        buttonLayout->addWidget(closeButton);
        layout->addRow(buttonLayout);

        connect(copyButton, &QPushButton::clicked, [banner]() {
            QApplication::clipboard()->setText(banner);
        });
        connect(closeButton, &QPushButton::clicked, this, &QDialog::accept);
    }
};

// ============================
// 主窗口类
// ============================
class MainWindow : public QMainWindow {
    Q_OBJECT
public:
    MainWindow() : QMainWindow(), totalPorts(0), scannedPorts(0) {
        settings = new ScannerSettings(this);
        recognizer = new ServiceRecognizer(this);
        setupUI();
        connectSignals();

        // 配置线程池
        QThreadPool::globalInstance()->setMaxThreadCount(settings->threadCount);

        // 显示法律声明
        showLegalNotice();
    }

    ~MainWindow() {
        stopScan();
        QThreadPool::globalInstance()->waitForDone();
    }

private:
    void setupUI() {
        setWindowTitle("skyPortscan3.0");
        resize(1200, 700);
        setWindowIcon(QIcon(":/icons/scanner.png"));

        // 创建中心部件
        QWidget *centralWidget = new QWidget(this);
        setCentralWidget(centralWidget);

        // 主布局
        QVBoxLayout *mainLayout = new QVBoxLayout(centralWidget);

        // 工具栏
        QToolBar *toolBar = new QToolBar("工具栏", this);
        addToolBar(Qt::TopToolBarArea, toolBar);

        scanAction = new QAction(QIcon(":/icons/scan.png"), "开始扫描", this);
        stopAction = new QAction(QIcon(":/icons/stop.png"), "停止", this);
        exportAction = new QAction(QIcon(":/icons/export.png"), "导出结果", this);
        settingsAction = new QAction(QIcon(":/icons/settings.png"), "设置", this);

        toolBar->addAction(scanAction);
        toolBar->addAction(stopAction);
        toolBar->addAction(exportAction);
        toolBar->addAction(settingsAction);

        // 菜单栏
        QMenu *fileMenu = menuBar()->addMenu("文件");
        fileMenu->addAction(scanAction);
        fileMenu->addAction(stopAction);
        fileMenu->addAction(exportAction);
        fileMenu->addSeparator();
        fileMenu->addAction("退出", this, &QWidget::close);

        QMenu *toolsMenu = menuBar()->addMenu("工具");
        toolsMenu->addAction(settingsAction);
        toolsMenu->addAction("查看日志", this, &MainWindow::openLogFile);

        QMenu *helpMenu = menuBar()->addMenu("帮助");
        helpMenu->addAction("关于", this, &MainWindow::showAbout);

        // 输入区域
        QGroupBox *inputGroup = new QGroupBox("扫描目标", this);
        QHBoxLayout *inputLayout = new QHBoxLayout(inputGroup);

        targetEdit = new QLineEdit("localhost", this);
        startPortEdit = new QLineEdit("1", this);
        endPortEdit = new QLineEdit("10000", this);

        inputLayout->addWidget(new QLabel("目标:"));
        inputLayout->addWidget(targetEdit);
        inputLayout->addWidget(new QLabel("起始端口:"));
        inputLayout->addWidget(startPortEdit);
        inputLayout->addWidget(new QLabel("结束端口:"));
        inputLayout->addWidget(endPortEdit);

        // 服务过滤
        serviceFilterCombo = new QComboBox(this);
        serviceFilterCombo->addItem("所有服务");
        serviceFilterCombo->addItem("Web服务");
        serviceFilterCombo->addItem("数据库");
        serviceFilterCombo->addItem("远程访问");
        serviceFilterCombo->addItem("文件传输");

        inputLayout->addWidget(new QLabel("服务过滤:"));
        inputLayout->addWidget(serviceFilterCombo);

        mainLayout->addWidget(inputGroup);

        // 结果区域
        QTabWidget *resultTabs = new QTabWidget(this);
        mainLayout->addWidget(resultTabs, 1);

        // 表格视图
        QWidget *tableView = new QWidget;
        QVBoxLayout *tableLayout = new QVBoxLayout(tableView);

        resultsTable = new QTableWidget(0, 8, this);
        QStringList headers = {"端口", "服务", "版本", "标题", "Web框架", "类别", "状态", "Banner"};
        resultsTable->setHorizontalHeaderLabels(headers);
        resultsTable->setColumnWidth(0, 60);
        resultsTable->setColumnWidth(1, 120);
        resultsTable->setColumnWidth(2, 80);
        resultsTable->setColumnWidth(3, 200);
        resultsTable->setColumnWidth(4, 120);
        resultsTable->setColumnWidth(5, 80);
        resultsTable->setColumnWidth(6, 60);
        resultsTable->horizontalHeader()->setSectionResizeMode(7, QHeaderView::Stretch);

        // 设置表格只读
        resultsTable->setEditTriggers(QAbstractItemView::NoEditTriggers);
        resultsTable->setSelectionBehavior(QAbstractItemView::SelectRows);
        resultsTable->setSelectionMode(QAbstractItemView::SingleSelection);

        tableLayout->addWidget(resultsTable);
        resultTabs->addTab(tableView, "详细结果");

        // 图表视图
        QWidget *chartView = new QWidget;
        QVBoxLayout *chartLayout = new QVBoxLayout(chartView);

        serviceChart = new QChartView(this);
        serviceChart->setRenderHint(QPainter::Antialiasing);
        chartLayout->addWidget(serviceChart);

        resultTabs->addTab(chartView, "服务分布");

        // 进度条
        progressBar = new QProgressBar(this);
        progressBar->setRange(0, 100);
        progressBar->setTextVisible(true);
        progressBar->setFormat("扫描进度: %p%");
        mainLayout->addWidget(progressBar);

        // 状态栏
        statusBar()->showMessage("准备就绪");

        // 连接工具栏动作
        connect(scanAction, &QAction::triggered, this, &MainWindow::startScan);
        connect(stopAction, &QAction::triggered, this, &MainWindow::stopScan);
        connect(exportAction, &QAction::triggered, this, &MainWindow::exportResults);
        connect(settingsAction, &QAction::triggered, this, &MainWindow::showSettings);

        // 禁用停止按钮
        stopAction->setEnabled(false);
    }

    void connectSignals() {
        // 服务过滤
        connect(serviceFilterCombo, QOverload<int>::of(&QComboBox::currentIndexChanged),
                this, &MainWindow::applyServiceFilter);

        // 双击查看详情
        connect(resultsTable, &QTableWidget::itemDoubleClicked, [this](QTableWidgetItem *item) {
            int row = item->row();
            showPortDetails(
                resultsTable->item(row, 0)->text().toInt(),
                resultsTable->item(row, 1)->text(),
                resultsTable->item(row, 2)->text(),
                resultsTable->item(row, 3)->text(),
                resultsTable->item(row, 4)->text(),
                resultsTable->item(row, 5)->text(),
                resultsTable->item(row, 7)->toolTip()
                );
        });
    }

    void showLegalNotice() {
        if (settings->value("legalAccepted", false).toBool()) return;

        int result = QMessageBox::information(this, "法律声明",
                                              "端口扫描工具使用声明：\n\n"
                                              "1. 仅扫描您拥有合法权限的目标系统\n"
                                              "2. 禁止用于非法目的或未经授权的扫描\n"
                                              "3. 使用本工具即表示您同意承担所有相关责任\n\n"
                                              "请确认您已理解并同意以上条款",
                                              QMessageBox::Ok | QMessageBox::Cancel);

        if (result == QMessageBox::Ok) {
            settings->setValue("legalAccepted", true);
        } else {
            QApplication::exit(0); // 退出整个程序
        }
    }

    void logError(const QString &message) {
        QString logPath = QStandardPaths::writableLocation(QStandardPaths::AppDataLocation) + "/scan_errors.log";
        QFile logFile(logPath);

        if (logFile.open(QIODevice::WriteOnly | QIODevice::Append)) {
            QTextStream stream(&logFile);
            stream << QDateTime::currentDateTime().toString(Qt::ISODate)
                   << " - " << message << "\n";
            logFile.close();
        }
    }

    void openLogFile() {
        QString logPath = QStandardPaths::writableLocation(QStandardPaths::AppDataLocation) + "/scan_errors.log";
        QDesktopServices::openUrl(QUrl::fromLocalFile(logPath));
    }

    void showAbout() {
        QMessageBox::about(this, "关于端口扫描器",
                           "高级端口扫描器 v2.0\n\n"
                           "功能特性：\n"
                           "- 多线程端口扫描\n"
                           "- 服务识别与版本检测\n"
                           "- Web框架识别\n"
                           "- 结果可视化分析\n"
                           "- 代理支持\n\n"
                           "© 2025 网络安全工具集");
    }

    QAction *scanAction;
    QAction *stopAction;
    QAction *exportAction;
    QAction *settingsAction;

private slots:
    void startScan() {
        // 验证输入
        bool ok;
        int start = startPortEdit->text().toInt(&ok);
        if (!ok || start < 1 || start > 65535) {
            QMessageBox::warning(this, "输入错误", "起始端口无效");
            return;
        }

        int end = endPortEdit->text().toInt(&ok);
        if (!ok || end < start || end > 65535) {
            QMessageBox::warning(this, "输入错误", "结束端口无效");
            return;
        }

        // 检查SYN扫描权限
        if (settings->scanMode == ScannerSettings::SYN_SCAN) {
            if (!checkAdminPrivileges()) {
                QMessageBox::warning(this, "权限不足", "SYN扫描需要管理员/root权限");
                return;
            }
        }

        // 准备扫描
        resultsTable->setRowCount(0);
        scanAction->setEnabled(false);
        stopAction->setEnabled(true);
        exportAction->setEnabled(false);
        settingsAction->setEnabled(false);
        serviceChart->chart()->removeAllSeries();
        statusBar()->showMessage("解析目标主机名...");

        // 重置计数器
        totalPorts = end - start + 1;
        scannedPorts = 0;
        foundPorts.clear();
        serviceDistribution.clear();

        // 更新线程池大小
        QThreadPool::globalInstance()->setMaxThreadCount(settings->threadCount);

        // 开始DNS解析
        QString target = targetEdit->text();
        QHostInfo::lookupHost(target, this, [=](const QHostInfo &info) {
            if (info.error() != QHostInfo::NoError) {
                logError("DNS解析失败: " + info.errorString());
                QMessageBox::warning(this, "解析错误", "无法解析主机名: " + info.errorString());
                statusBar()->showMessage("准备就绪");
                return;
            }

            QHostAddress ipv4Address;
            for (const QHostAddress &address : info.addresses()) {
                if (address.protocol() == QAbstractSocket::IPv4Protocol) {
                    ipv4Address = address;
                    break;
                }
            }

            if (ipv4Address.isNull() && !info.addresses().isEmpty()) {
                ipv4Address = info.addresses().first(); // 没有IPv4，使用第一个地址
            }

            QString ipAddress = ipv4Address.isNull() ? target : ipv4Address.toString();
            statusBar()->showMessage("扫描中...");
            progressBar->setValue(0);

            // 创建扫描任务
            for (int port = start; port <= end; ++port) {
                ScanTask *task = new ScanTask(ipAddress, port, settings, recognizer, this);
                QThreadPool::globalInstance()->start(task);
            }
        });
    }


    bool checkAdminPrivileges() {
// Windows: 检查是否以管理员身份运行
#ifdef Q_OS_WIN
        BOOL isAdmin = FALSE;
        HANDLE hToken = NULL;

        if (OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &hToken)) {
            TOKEN_ELEVATION Elevation;
            DWORD cbSize = sizeof(TOKEN_ELEVATION);

            if (GetTokenInformation(hToken, TokenElevation, &Elevation, sizeof(Elevation), &cbSize)) {
                isAdmin = Elevation.TokenIsElevated;
            }
        }

        if (hToken) CloseHandle(hToken);
        return isAdmin;

        // Linux/macOS: 检查root权限
#else
        return geteuid() == 0;
#endif
    }

    void stopScan() {
        QThreadPool::globalInstance()->clear();
        scanAction->setEnabled(true);
        stopAction->setEnabled(false);
        exportAction->setEnabled(true);
        settingsAction->setEnabled(true);
        statusBar()->showMessage("扫描已停止");
    }

    void portFound(int port, const QString &service, const QString &version,
                   const QString &title, const QString &framework,
                   const QString &category, const QString &banner) {
        // 确保不重复添加
        if (foundPorts.contains(port)) return;
        foundPorts.insert(port);

        // 更新服务分布统计
        if (!category.isEmpty()) {
            serviceDistribution[category]++;
        } else {
            serviceDistribution["其他"]++;
        }

        int row = resultsTable->rowCount();
        resultsTable->insertRow(row);

        resultsTable->setItem(row, 0, new QTableWidgetItem(QString::number(port)));
        resultsTable->setItem(row, 1, new QTableWidgetItem(service));
        resultsTable->setItem(row, 2, new QTableWidgetItem(version));
        resultsTable->setItem(row, 3, new QTableWidgetItem(title));
        resultsTable->setItem(row, 4, new QTableWidgetItem(framework));
        resultsTable->setItem(row, 5, new QTableWidgetItem(category));
        resultsTable->setItem(row, 6, new QTableWidgetItem("开放"));

        // 处理长banner显示
        QString displayBanner = banner;
        if (banner.length() > 200) {
            displayBanner = banner.left(200) + "...";
        }
        QTableWidgetItem *bannerItem = new QTableWidgetItem(displayBanner);
        resultsTable->setItem(row, 7, bannerItem);

        // 设置完整banner为工具提示
        bannerItem->setToolTip(banner);

        // 更新图表
        updateServiceChart();
    }

    void taskCompleted() {
        scannedPorts++;
        int progress = (scannedPorts * 100) / totalPorts;
        progressBar->setValue(progress);

        if (scannedPorts >= totalPorts) {
            onScanFinished();
        }
    }

    void onScanFinished() {
        statusBar()->showMessage(QString("扫描完成，发现 %1 个开放端口").arg(foundPorts.size()));
        progressBar->setValue(100);
        stopScan();
    }

    void showPortDetails(int port, const QString &service, const QString &version,
                         const QString &title, const QString &framework,
                         const QString &category, const QString &banner) {
        PortDetailsDialog dialog(port, service, version, title, framework, category, banner, this);
        dialog.exec();
    }

    void applyServiceFilter(int index) {
        QString filterCategory = "";

        switch (index) {
        case 1: filterCategory = "web"; break;
        case 2: filterCategory = "database"; break;
        case 3: filterCategory = "remote"; break;
        case 4: filterCategory = "file"; break;
        }

        for (int row = 0; row < resultsTable->rowCount(); ++row) {
            bool visible = filterCategory.isEmpty() ||
                           resultsTable->item(row, 5)->text() == filterCategory;
            resultsTable->setRowHidden(row, !visible);
        }
    }

    void updateServiceChart() {
        QChart *chart = new QChart();
        chart->setTitle("服务类型分布");

        QPieSeries *series = new QPieSeries();

        for (auto it = serviceDistribution.begin(); it != serviceDistribution.end(); ++it) {
            series->append(it.key(), it.value());
        }

        // 设置切片标签
        for (QPieSlice *slice : series->slices()) {
            slice->setLabel(QString("%1 (%2)").arg(slice->label()).arg(slice->value()));
            slice->setLabelVisible(true);
        }

        chart->addSeries(series);
        chart->legend()->setAlignment(Qt::AlignRight);

        serviceChart->setChart(chart);
    }

    void exportResults() {
        QString fileName = QFileDialog::getSaveFileName(
            this,
            "导出结果",
            "",
            "CSV文件 (*.csv);;JSON文件 (*.json);;所有文件 (*.*)"
            );

        if (fileName.isEmpty()) return;

        if (fileName.endsWith(".json", Qt::CaseInsensitive)) {
            exportToJson(fileName);
        } else {
            // 确保CSV扩展名
            if (!fileName.endsWith(".csv", Qt::CaseInsensitive)) {
                fileName += ".csv";
            }
            exportToCsv(fileName);
        }
    }

    void exportToCsv(const QString &fileName) {
        QFile file(fileName);
        if (!file.open(QIODevice::WriteOnly | QIODevice::Text)) {
            logError("导出失败: " + file.errorString());
            QMessageBox::warning(this, "导出错误", "无法创建文件: " + file.errorString());
            return;
        }

        QTextStream out(&file);
        out << "端口,服务,版本,标题,Web框架,类别,状态,Banner\n";

        for (int i = 0; i < resultsTable->rowCount(); ++i) {
            if (resultsTable->isRowHidden(i)) continue;

            out << resultsTable->item(i, 0)->text() << ","
                << resultsTable->item(i, 1)->text() << ","
                << resultsTable->item(i, 2)->text() << ","
                << "\"" << resultsTable->item(i, 3)->text().replace("\"", "\"\"") << "\","
                << "\"" << resultsTable->item(i, 4)->text().replace("\"", "\"\"") << "\","
                << resultsTable->item(i, 5)->text() << ","
                << resultsTable->item(i, 6)->text() << ","
                << "\"" << resultsTable->item(i, 7)->toolTip().replace("\"", "\"\"") << "\"\n";
        }

        file.close();
        QMessageBox::information(this, "导出成功", "结果已导出到: " + fileName);
    }

    void exportToJson(const QString &fileName) {
        QFile file(fileName);
        if (!file.open(QIODevice::WriteOnly | QIODevice::Text)) {
            logError("导出失败: " + file.errorString());
            QMessageBox::warning(this, "导出错误", "无法创建文件: " + file.errorString());
            return;
        }

        QJsonArray results;

        for (int i = 0; i < resultsTable->rowCount(); ++i) {
            if (resultsTable->isRowHidden(i)) continue;

            QJsonObject portInfo;
            portInfo["port"] = resultsTable->item(i, 0)->text().toInt();
            portInfo["service"] = resultsTable->item(i, 1)->text();
            portInfo["version"] = resultsTable->item(i, 2)->text();
            portInfo["title"] = resultsTable->item(i, 3)->text();
            portInfo["framework"] = resultsTable->item(i, 4)->text();
            portInfo["category"] = resultsTable->item(i, 5)->text();
            portInfo["status"] = resultsTable->item(i, 6)->text();
            portInfo["banner"] = resultsTable->item(i, 7)->toolTip();

            results.append(portInfo);
        }

        QJsonDocument doc(results);
        file.write(doc.toJson());
        file.close();

        QMessageBox::information(this, "导出成功", "结果已导出到: " + fileName);
    }

    void showSettings() {
        SettingsDialog dialog(settings, this);
        dialog.exec();
    }

private:
    ScannerSettings *settings;
    ServiceRecognizer *recognizer;

    // UI控件
    QLineEdit *targetEdit;
    QLineEdit *startPortEdit;
    QLineEdit *endPortEdit;
    QComboBox *serviceFilterCombo;
    QProgressBar *progressBar;
    QTableWidget *resultsTable;
    QChartView *serviceChart;

    // 扫描状态
    int totalPorts;
    int scannedPorts;
    QSet<int> foundPorts;
    QMap<QString, int> serviceDistribution;
};

// ============================
// 主函数
// ============================
int main(int argc, char *argv[]) {
    QApplication app(argc, argv);

    // 设置应用程序信息
    QCoreApplication::setOrganizationName("PortScanner");
    QCoreApplication::setApplicationName("AdvancedPortScanner");

    // 创建必要目录
    QString appDataDir = QStandardPaths::writableLocation(QStandardPaths::AppDataLocation);
    QDir().mkpath(appDataDir);

    MainWindow window;

    // 居中显示窗口 - 使用 QScreen 替代 QDesktopWidget
    QScreen *screen = QGuiApplication::primaryScreen();
    if (screen) {
        QRect screenGeometry = screen->geometry();
        int x = (screenGeometry.width() - window.width()) / 2;
        int y = (screenGeometry.height() - window.height()) / 2;
        window.move(x, y);
    }

    window.show();
    return app.exec();
}
#include "main.moc"
