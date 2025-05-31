#include<Windows.h>
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
#include <QMutex>
#include <QSet>
#include <QDir>
#include <QProcess>
#include <QCoreApplication>
#include <QHostInfo>
#include <QFileDialog> // 添加文件对话框支持

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
    {"proxy", "HTTP", 3128},
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

// 扫描任务类（多线程）
class ScanTask : public QRunnable {
public:
    ScanTask(const QString &target, int port, QObject *receiver)
        : m_target(target), m_port(port), m_receiver(receiver) {}

    void run() override {
        QTcpSocket socket;
        socket.connectToHost(m_target, m_port);

        if (socket.waitForConnected(500)) {
            QString service = "unknown";
            QString banner = "";

            // 尝试读取banner
            if (socket.waitForReadyRead(1000)) {
                banner = socket.read(1024).trimmed();
                service = detectService(m_port, banner);
            } else {
                service = detectService(m_port, "");
            }

            QString title = "";
            if (service == "http" || service == "https") {
                title = fetchHttpTitle(m_port);
            }

            QMetaObject::invokeMethod(m_receiver, "portFound",
                                      Q_ARG(int, m_port),
                                      Q_ARG(QString, service),
                                      Q_ARG(QString, title),
                                      Q_ARG(QString, banner));

            socket.disconnectFromHost();
        }
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

    QString fetchHttpTitle(int port) {
        QString protocol = (port == 443) ? "https" : "http";
        QUrl url(protocol + "://" + m_target);
        QEventLoop loop;
        QString title = "";

        QNetworkAccessManager manager;
        QNetworkRequest request(url);
        request.setRawHeader("User-Agent", "PortScanner/1.0");

        // 设置重定向策略 - 修复 FollowRedirectsAttribute 问题
        manager.setRedirectPolicy(QNetworkRequest::NoLessSafeRedirectPolicy);

        // 设置超时定时器
        QTimer timer;
        timer.setSingleShot(true);
        timer.start(10000); // 10秒超时

        QNetworkReply *reply = manager.get(request);

        // 连接超时信号
        QObject::connect(&timer, &QTimer::timeout, [&]() {
            reply->abort();
            loop.quit();
        });

        // 连接完成信号
        QObject::connect(reply, &QNetworkReply::finished, [&]() {
            if (reply->error() == QNetworkReply::NoError) {
                QByteArray data = reply->readAll();
                QRegularExpression re("<title>(.*?)</title>",
                                      QRegularExpression::CaseInsensitiveOption);
                QRegularExpressionMatch match = re.match(data);
                if (match.hasMatch()) {
                    title = match.captured(1).left(50); // 截取前50字符
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
    QObject *m_receiver;
};

// 主窗口类
class MainWindow : public QMainWindow {
    Q_OBJECT
public:
    MainWindow() : QMainWindow(), totalPorts(0), scannedPorts(0) {
        setupUI();
        connectSignals();

        // 配置线程池
        QThreadPool::globalInstance()->setMaxThreadCount(75); // 75个线程并发
    }

    ~MainWindow() {
        QThreadPool::globalInstance()->waitForDone();
    }

private:
    void setupUI() {
        setWindowTitle("端口扫描器");
        resize(1000, 600);

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

        QHBoxLayout *buttonLayout = new QHBoxLayout();
        buttonLayout->addWidget(scanButton);
        buttonLayout->addWidget(stopButton);
        buttonLayout->addWidget(exportButton);

        // 添加进度条
        progressBar = new QProgressBar(this);
        progressBar->setRange(0, 100);
        progressBar->setTextVisible(true);
        progressBar->setFormat("扫描进度: %p%");

        // 结果表格
        resultsTable = new QTableWidget(0, 5, this);
        QStringList headers = {"端口", "服务", "状态", "标题", "Banner"};
        resultsTable->setHorizontalHeaderLabels(headers);
        resultsTable->setColumnWidth(0, 80);
        resultsTable->setColumnWidth(1, 100);
        resultsTable->setColumnWidth(2, 80);
        resultsTable->horizontalHeader()->setSectionResizeMode(3, QHeaderView::Stretch);
        resultsTable->horizontalHeader()->setSectionResizeMode(4, QHeaderView::Interactive);

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
        statusBar()->showMessage("扫描中...");
        progressBar->setValue(0);

        // 重置计数器
        scannedPorts = 0;
        totalPorts = end - start + 1;
        foundPorts.clear();

        // 开始扫描
        QString target = targetEdit->text();

        // 解析主机名（如果是域名）
        QHostInfo hostInfo = QHostInfo::fromName(target);
        if (hostInfo.error() != QHostInfo::NoError) {
            QMessageBox::warning(this, "解析错误", "无法解析主机名: " + hostInfo.errorString());
            scanButton->setEnabled(true);
            stopButton->setEnabled(false);
            return;
        }

        QString ipAddress = hostInfo.addresses().isEmpty() ? target : hostInfo.addresses().first().toString();

        int scanedport=0;

        for (int port = start; port <= end; ++port) {
            ScanTask *task = new ScanTask(ipAddress, port, this);
            QThreadPool::globalInstance()->start(task);
            scanedport=port;
            progressing(scanedport,end);

        }


    }

    void stopScan() {
        QThreadPool::globalInstance()->clear();
        scanButton->setEnabled(true);
        stopButton->setEnabled(false);
        exportButton->setEnabled(true);
        statusBar()->showMessage("扫描已停止");
        onScanFinished();
    }

    void portFound(int port, const QString &service, const QString &title, const QString &banner) {
        // 确保不重复添加
        if (foundPorts.contains(port)) return;
        foundPorts.insert(port);

        int row = resultsTable->rowCount();
        resultsTable->insertRow(row);

        resultsTable->setItem(row, 0, new QTableWidgetItem(QString::number(port)));
        resultsTable->setItem(row, 1, new QTableWidgetItem(service));
        resultsTable->setItem(row, 2, new QTableWidgetItem("开放"));
        resultsTable->setItem(row, 3, new QTableWidgetItem(title));
        resultsTable->setItem(row, 4, new QTableWidgetItem(banner));

        // 更新进度
        scannedPorts++;
        float progress = (scannedPorts / totalPorts) * 100;
        progressBar->setValue(progress);

        if (scannedPorts >= totalPorts) {
            onScanFinished();
        }
    }
    void progressing(int scannedPorts,int totalPorts){
        float progress = (scannedPorts / totalPorts) * 100;
        progressBar->setValue(progress);

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
        out << "端口,服务,状态,标题,Banner\n";

        for (int i = 0; i < resultsTable->rowCount(); ++i) {
            out << resultsTable->item(i, 0)->text() << ","
                << resultsTable->item(i, 1)->text() << ","
                << resultsTable->item(i, 2)->text() << ","
                << "\"" << resultsTable->item(i, 3)->text().replace("\"", "\"\"") << "\","
                << "\"" << resultsTable->item(i, 4)->text().replace("\"", "\"\"") << "\"\n";
        }

        file.close();
        QMessageBox::information(this, "导出成功", "结果已导出到: " + fileName);
    }

    void onScanFinished() {
        scanButton->setEnabled(true);
        stopButton->setEnabled(false);
        exportButton->setEnabled(true);
        statusBar()->showMessage("扫描完成");
        progressBar->setValue(100);
    }

private:
    QLineEdit *targetEdit;
    QLineEdit *startPortEdit;
    QLineEdit *endPortEdit;
    QPushButton *scanButton;
    QPushButton *stopButton;
    QPushButton *exportButton;
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

    MainWindow window;
    window.show();
    return app.exec();
}

#include "main.moc"
