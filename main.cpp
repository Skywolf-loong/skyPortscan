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

// 服务识别信息结构体
struct ServiceInfo {
    QString name;
    QString bannerPattern;
    int defaultPort;
};

// 全局服务识别列表
QVector<ServiceInfo> serviceList = {
    {"http", "HTTP", 80},
    {"https", "HTTP", 443},
    {"ssh", "SSH", 22},
    {"ftp", "220", 21},
    {"smtp", "220", 25},
    {"pop3", "+OK", 110},
    {"imap", "* OK", 143},
    {"dns", "DNS", 53},
    {"telnet", "", 23},
    {"proxy", "HTTP", 8080},
    {"mysql", "mysql", 3306},
    {"postgresql", "postgres", 5432},
    {"redis", "REDIS", 6379},
    {"mongodb", "mongod", 27017},
    {"rdp", "", 3389},
    {"vnc", "RFB", 5900},
    {"sip", "SIP", 5060},
    {"ntp", "", 123},
    {"snmp", "", 161},
    {"ldap", "", 389},
};

// 常见Web框架识别模式
QMap<QString, QString> webFrameworks = {
    {"Apache", "Server: Apache"},
    {"Nginx", "Server: nginx"},
    {"IIS", "Server: Microsoft-IIS"},
    {"Tomcat", "Server: Apache-Coyote"},
    {"Node.js", "X-Powered-By: Express"},
    {"WordPress", "X-Powered-By: PHP"},
    {"Drupal", "X-Generator: Drupal"},
    {"Joomla", "X-Powered-By: Joomla"},
    {"Laravel", "X-Powered-By: Laravel"},
    {"Django", "X-Powered-By: Django"},
    {"Flask", "Server: Werkzeug"},
    {"Ruby on Rails", "X-Powered-By: Phusion Passenger"},
    {"ASP.NET", "X-Powered-By: ASP.NET"}
};

// 设置类
class ScannerSettings : public QObject {
    Q_OBJECT
public:
    ScannerSettings(QObject *parent = nullptr) : QObject(parent) {
        load();
    }

    void save() {
        QSettings settings("PortScanner", "Settings");
        settings.setValue("userAgent", userAgent);
        settings.setValue("threadCount", threadCount);
        settings.setValue("connectTimeout", connectTimeout);
        settings.setValue("readTimeout", readTimeout);
        settings.setValue("httpTimeout", httpTimeout);
    }

    void load() {
        QSettings settings("PortScanner", "Settings");
        userAgent = settings.value("userAgent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36").toString();
        threadCount = settings.value("threadCount", 50).toInt();
        connectTimeout = settings.value("connectTimeout", 500).toInt();
        readTimeout = settings.value("readTimeout", 1000).toInt();
        httpTimeout = settings.value("httpTimeout", 3000).toInt();
    }

    QString userAgent;
    int threadCount;
    int connectTimeout;
    int readTimeout;
    int httpTimeout;
};

// 设置对话框
class SettingsDialog : public QDialog {
    Q_OBJECT
public:
    SettingsDialog(ScannerSettings *settings, QWidget *parent = nullptr)
        : QDialog(parent), m_settings(settings) {
        setWindowTitle("扫描设置");
        setFixedSize(500, 300);

        QFormLayout *layout = new QFormLayout(this);

        // User-Agent
        userAgentEdit = new QLineEdit(m_settings->userAgent, this);
        layout->addRow("User-Agent:", userAgentEdit);

        // 线程数
        threadCountSpin = new QSpinBox(this);
        threadCountSpin->setRange(1, 500);
        threadCountSpin->setValue(m_settings->threadCount);
        layout->addRow("线程数:", threadCountSpin);

        // 连接超时
        connectTimeoutSpin = new QSpinBox(this);
        connectTimeoutSpin->setRange(100, 10000);
        connectTimeoutSpin->setValue(m_settings->connectTimeout);
        connectTimeoutSpin->setSuffix(" ms");
        layout->addRow("连接超时:", connectTimeoutSpin);

        // 读取超时
        readTimeoutSpin = new QSpinBox(this);
        readTimeoutSpin->setRange(100, 10000);
        readTimeoutSpin->setValue(m_settings->readTimeout);
        readTimeoutSpin->setSuffix(" ms");
        layout->addRow("读取超时:", readTimeoutSpin);

        // HTTP超时
        httpTimeoutSpin = new QSpinBox(this);
        httpTimeoutSpin->setRange(1000, 10000);
        httpTimeoutSpin->setValue(m_settings->httpTimeout);
        httpTimeoutSpin->setSuffix(" ms");
        layout->addRow("HTTP超时:", httpTimeoutSpin);

        // 按钮
        QHBoxLayout *buttonLayout = new QHBoxLayout();
        QPushButton *saveButton = new QPushButton("保存", this);
        QPushButton *cancelButton = new QPushButton("取消", this);
        buttonLayout->addWidget(saveButton);
        buttonLayout->addWidget(cancelButton);

        layout->addRow(buttonLayout);

        connect(saveButton, &QPushButton::clicked, this, &SettingsDialog::saveSettings);

        connect(cancelButton, &QPushButton::clicked, this, &SettingsDialog::reject);
    }

private slots:
    void saveSettings() {
        m_settings->userAgent = userAgentEdit->text();
        m_settings->threadCount = threadCountSpin->value();
        m_settings->connectTimeout = connectTimeoutSpin->value();
        m_settings->readTimeout = readTimeoutSpin->value();
        m_settings->httpTimeout = httpTimeoutSpin->value();
        m_settings->save();
        accept();
    }

private:
    ScannerSettings *m_settings;
    QLineEdit *userAgentEdit;
    QSpinBox *threadCountSpin;
    QSpinBox *connectTimeoutSpin;
    QSpinBox *readTimeoutSpin;
    QSpinBox *httpTimeoutSpin;
};

// 扫描任务类（多线程）
class ScanTask : public QRunnable {
public:
    ScanTask(const QString &target, int port, ScannerSettings *settings, QObject *receiver)
        : m_target(target), m_port(port), m_settings(settings), m_receiver(receiver) {}

    void run() override {
        QTcpSocket socket;
        socket.connectToHost(m_target, m_port);

        if (socket.waitForConnected(m_settings->connectTimeout)) {
            QString service = "unknown";
            QString banner = ""; // 保存banner
            QString framework = "";

            // 尝试读取banner
            if (socket.waitForReadyRead(m_settings->readTimeout)) {
                banner = socket.read(1024).trimmed();
                service = detectService(m_port, banner);

                // 特殊服务处理
                if (service == "ftp") {
                    banner = tryFTPAnonymous(socket, banner); // 传递banner
                }
            } else {
                service = detectService(m_port, "");
            }

            QString title = "";
            QString webFramework = "";
            if (service == "http" || service == "https") {
                title = fetchHttpTitle(m_port);
                webFramework = detectWebFramework();
            }

            QMetaObject::invokeMethod(m_receiver, "portFound",
                                      Q_ARG(int, m_port),
                                      Q_ARG(QString, service),
                                      Q_ARG(QString, title),
                                      Q_ARG(QString, banner),
                                      Q_ARG(QString, webFramework));

            socket.disconnectFromHost();
        }

        // 通知任务完成
        QMetaObject::invokeMethod(m_receiver, "taskCompleted");
    }

private:
    QString detectService(int port, const QString &banner) {
        // 首先根据端口匹配
        for (const auto &service : serviceList) {
            if (service.defaultPort == port) {
                return service.name;
            }
        }

        // 然后根据banner匹配
        if (!banner.isEmpty()) {
            for (const auto &service : serviceList) {
                if (!service.bannerPattern.isEmpty() &&
                    banner.contains(service.bannerPattern, Qt::CaseInsensitive)) {
                    return service.name;
                }
            }

            // 特殊服务识别
            if (banner.contains("SSH", Qt::CaseInsensitive)) return "ssh";
            if (banner.contains("HTTP", Qt::CaseInsensitive)) return "http";
            if (banner.contains("FTP", Qt::CaseInsensitive)) return "ftp";
            if (banner.contains("SMTP", Qt::CaseInsensitive)) return "smtp";
            if (banner.contains("POP3", Qt::CaseInsensitive)) return "pop3";
            if (banner.contains("IMAP", Qt::CaseInsensitive)) return "imap";
            if (banner.contains("DNS", Qt::CaseInsensitive)) return "dns";
        }

        return "unknown";
    }

    QString detectWebFramework() {
        if (httpResponse.isEmpty()) return "";

        // 将HTTP响应头组合成字符串
        QString headers;
        for (const auto &header : httpResponse) {
            headers += header.first + ": " + header.second + "\n";
        }

        for (auto it = webFrameworks.begin(); it != webFrameworks.end(); ++it) {
            if (headers.contains(it.value(), Qt::CaseInsensitive)) {
                return it.key();
            }
        }

        // 尝试通过其他方式识别
        if (headers.contains("X-Powered-By")) {
            QRegularExpression re("X-Powered-By: (.+)", QRegularExpression::CaseInsensitiveOption);
            QRegularExpressionMatch match = re.match(headers);
            if (match.hasMatch()) {
                return match.captured(1);
            }
        }

        return "";
    }

    QString tryFTPAnonymous(QTcpSocket &socket, const QString &initialBanner) {
        QString response = initialBanner; // 使用传入的banner

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
        QUrl url(protocol + "://" + m_target);
        QEventLoop loop;
        QString title = "";

        QNetworkAccessManager manager;
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
                // 保存HTTP响应头用于框架识别
                httpResponse = reply->rawHeaderPairs();

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
                    title = titleMatch.captured(1).left(100); // 截取前100字符
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
    QObject *m_receiver;
    QList<QNetworkReply::RawHeaderPair> httpResponse;
};

// 主窗口类
class MainWindow : public QMainWindow {
    Q_OBJECT
public:
    MainWindow() : QMainWindow(), totalPorts(0), scannedPorts(0) {
        settings = new ScannerSettings(this);
        setupUI();
        connectSignals();

        // 配置线程池
        QThreadPool::globalInstance()->setMaxThreadCount(settings->threadCount);
    }

    ~MainWindow() {
        stopScan();
        QThreadPool::globalInstance()->waitForDone();
    }

private:
    void setupUI() {
        setWindowTitle("skyportscan_2.0");
        resize(1200, 700);

        // 创建中心部件
        QWidget *centralWidget = new QWidget(this);
        setCentralWidget(centralWidget);

        // 布局
        QVBoxLayout *layout = new QVBoxLayout(centralWidget);

        // 输入区域
        QHBoxLayout *inputLayout = new QHBoxLayout();
        targetEdit = new QLineEdit("localhost", this);
        startPortEdit = new QLineEdit("1", this);

        endPortEdit = new QLineEdit("65500", this);

        inputLayout->addWidget(new QLabel("目标:"));
        inputLayout->addWidget(targetEdit);
        inputLayout->addWidget(new QLabel("起始端口:"));
        inputLayout->addWidget(startPortEdit);
        inputLayout->addWidget(new QLabel("结束端口:"));
        inputLayout->addWidget(endPortEdit);

        // 按钮
        scanButton = new QPushButton("开始扫描", this);
        stopButton = new QPushButton("停止", this);
        stopButton->setEnabled(false);
        exportButton = new QPushButton("导出结果", this);
        settingsButton = new QPushButton("设置", this);

        QHBoxLayout *buttonLayout = new QHBoxLayout();
        buttonLayout->addWidget(scanButton);
        buttonLayout->addWidget(stopButton);
        buttonLayout->addWidget(exportButton);
        buttonLayout->addWidget(settingsButton);

        // 添加进度条
        progressBar = new QProgressBar(this);
        progressBar->setRange(0, 100);
        progressBar->setTextVisible(true);
        progressBar->setFormat("扫描进度: %p%");

        // 结果表格
        resultsTable = new QTableWidget(0, 6, this);
        QStringList headers = {"端口", "服务", "状态", "标题", "Web框架", "Banner"};
        resultsTable->setHorizontalHeaderLabels(headers);
        resultsTable->setColumnWidth(0, 60);
        resultsTable->setColumnWidth(1, 80);
        resultsTable->setColumnWidth(2, 60);
        resultsTable->setColumnWidth(3, 200);
        resultsTable->setColumnWidth(4, 120);
        resultsTable->horizontalHeader()->setSectionResizeMode(5, QHeaderView::Stretch);

        // 设置表格只读
        resultsTable->setEditTriggers(QAbstractItemView::NoEditTriggers);
        resultsTable->setSelectionBehavior(QAbstractItemView::SelectRows);

        // 添加到主布局
        layout->addLayout(inputLayout);
        layout->addLayout(buttonLayout);
        layout->addWidget(progressBar);
        layout->addWidget(resultsTable);

        // 状态栏
        statusBar()->showMessage("准备就绪");
    }

    void connectSignals() {
        connect(scanButton, &QPushButton::clicked, this, &MainWindow::startScan);
        connect(stopButton, &QPushButton::clicked, this, &MainWindow::stopScan);
        connect(exportButton, &QPushButton::clicked, this, &MainWindow::exportResults);
        connect(settingsButton, &QPushButton::clicked, this, &MainWindow::showSettings);
    }

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

        // 准备扫描
        resultsTable->setRowCount(0);
        scanButton->setEnabled(false);
        stopButton->setEnabled(true);
        exportButton->setEnabled(false);
        settingsButton->setEnabled(false);
        statusBar()->showMessage("扫描中...");
        progressBar->setValue(0);

        // 重置计数器
        totalPorts = end - start + 1;
        scannedPorts = 0;
        foundPorts.clear();

        // 更新线程池大小
        QThreadPool::globalInstance()->setMaxThreadCount(settings->threadCount);

        // 开始扫描
        QString target = targetEdit->text();

        // 解析主机名（如果是域名）
        QHostInfo hostInfo = QHostInfo::fromName(target);
        if (hostInfo.error() != QHostInfo::NoError) {
            QMessageBox::warning(this, "解析错误", "无法解析主机名: " + hostInfo.errorString());
            scanButton->setEnabled(true);
            stopButton->setEnabled(false);
            settingsButton->setEnabled(true);
            return;
        }

        QString ipAddress = hostInfo.addresses().isEmpty() ? target : hostInfo.addresses().first().toString();

        // 创建扫描任务
        for (int port = start; port <= end; ++port) {
            ScanTask *task = new ScanTask(ipAddress, port, settings, this);
            QThreadPool::globalInstance()->start(task);
        }
    }

    void stopScan() {
        QThreadPool::globalInstance()->clear();
        scanButton->setEnabled(true);
        stopButton->setEnabled(false);
        exportButton->setEnabled(true);
        settingsButton->setEnabled(true);
        statusBar()->showMessage("扫描已停止");
    }

    void portFound(int port, const QString &service, const QString &title,
                   const QString &banner, const QString &framework) {
        // 确保不重复添加
        if (foundPorts.contains(port)) return;
        foundPorts.insert(port);

        int row = resultsTable->rowCount();
        resultsTable->insertRow(row);

        resultsTable->setItem(row, 0, new QTableWidgetItem(QString::number(port)));
        resultsTable->setItem(row, 1, new QTableWidgetItem(service));
        resultsTable->setItem(row, 2, new QTableWidgetItem("开放"));
        resultsTable->setItem(row, 3, new QTableWidgetItem(title));
        resultsTable->setItem(row, 4, new QTableWidgetItem(framework));

        // 处理长banner显示
        QString displayBanner = banner;
        if (banner.length() > 500) {
            displayBanner = banner.left(500) + "...";
        }
        resultsTable->setItem(row, 5, new QTableWidgetItem(displayBanner));

        // 设置完整banner为工具提示
        resultsTable->item(row, 5)->setToolTip(banner);
    }

    void taskCompleted() {
        scannedPorts++;
        int progress = (scannedPorts * 100) / totalPorts;
        progressBar->setValue(progress);

        if (scannedPorts >= totalPorts) {
            onScanFinished();
        }
    }

    void exportResults() {
        QString fileName = QFileDialog::getSaveFileName(
            this,
            "导出结果",
            "",
            "CSV文件 (*.csv);;所有文件 (*.*)"
        );

        if (fileName.isEmpty()) return;

        // 确保文件扩展名正确
        if (!fileName.endsWith(".csv", Qt::CaseInsensitive)) {
            fileName += ".csv";
        }

        QFile file(fileName);
        if (!file.open(QIODevice::WriteOnly | QIODevice::Text)) {
            QMessageBox::warning(this, "导出错误", "无法创建文件: " + file.errorString());
            return;
        }

        QTextStream out(&file);
        out << "端口,服务,状态,标题,Web框架,Banner\n";

        for (int i = 0; i < resultsTable->rowCount(); ++i) {
            out << resultsTable->item(i, 0)->text() << ","
                << resultsTable->item(i, 1)->text() << ","
                << resultsTable->item(i, 2)->text() << ","
                << "\"" << resultsTable->item(i, 3)->text().replace("\"", "\"\"") << "\","
                << "\"" << resultsTable->item(i, 4)->text().replace("\"", "\"\"") << "\","
                << "\"" << resultsTable->item(i, 5)->toolTip().replace("\"", "\"\"") << "\"\n";
        }

        file.close();
        QMessageBox::information(this, "导出成功", "结果已导出到: " + fileName);
    }

    void showSettings() {
        SettingsDialog dialog(settings, this);
        dialog.exec();
    }

    void onScanFinished() {
        scanButton->setEnabled(true);
        stopButton->setEnabled(false);
        exportButton->setEnabled(true);
        settingsButton->setEnabled(true);
        statusBar()->showMessage(QString("扫描完成，发现 %1 个开放端口").arg(foundPorts.size()));
        progressBar->setValue(100);
    }

private:
    ScannerSettings *settings;

    QLineEdit *targetEdit;
    QLineEdit *startPortEdit;
    QLineEdit *endPortEdit;
    QPushButton *scanButton;
    QPushButton *stopButton;
    QPushButton *exportButton;
    QPushButton *settingsButton;
    QProgressBar *progressBar;
    QTableWidget *resultsTable;

    int totalPorts;
    int scannedPorts;
    QSet<int> foundPorts;
};

// 打包辅助函数
void deployApplication() {
    QString appPath = QCoreApplication::applicationDirPath();
    QString appName = QCoreApplication::applicationFilePath();

    QProcess process;
    process.setWorkingDirectory(appPath);

#ifdef Q_OS_WIN
    // 使用 windeployqt 打包
    QString windeployqt = "windeployqt";
    QStringList args;
    args << "--release" << "--no-compiler-runtime" << appName;
    process.start(windeployqt, args);
    process.waitForFinished();

    // 复制必要的 MinGW DLL
    QString mingwPath = "D:/Qt/Tools/mingw1120_64/bin/"; // 修改为你的MinGW路径
    QStringList dlls = {"libgcc_s_seh-1.dll", "libstdc++-6.dll", "libwinpthread-1.dll"};

    for (const QString &dll : dlls) {
        QFile::copy(mingwPath + dll, appPath + "/" + dll);
    }
#endif

    QMessageBox::information(nullptr, "打包完成", "应用程序已打包到: " + appPath);
}

// 主函数
int main(int argc, char *argv[]) {
    QApplication app(argc, argv);

    // 检查是否在打包模式下运行
    if (argc > 1 && QString(argv[1]) == "--deploy") {
        deployApplication();
        return 0;
    }

    // 设置应用程序信息
    QCoreApplication::setOrganizationName("PortScanner");
    QCoreApplication::setApplicationName("AdvancedPortScanner");

    MainWindow window;
    window.show();
    return app.exec();
}

#include "main.moc"
