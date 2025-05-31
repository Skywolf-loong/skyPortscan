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
#include <QProgressBar> // 添加进度条支持

// 扫描线程类
class PortScanner : public QThread {
    Q_OBJECT
public:
    explicit PortScanner(QObject *parent = nullptr)
        : QThread(parent), abort(false) {}

    void scan(const QString &target, int startPort, int endPort) {
        this->target = target;
        this->startPort = startPort;
        this->endPort = endPort;
        abort = false;
        if (!isRunning()) start();
    }

    void stop() { abort = true; }

signals:
    void portFound(int port, const QString &service, const QString &title);
    void scanFinished();
    void scanProgress(int value);
    void statusMessage(const QString &msg);

protected:
    void run() override {
        int totalPorts = endPort - startPort + 1;
        int scanned = 0;

        for (int port = startPort; port <= endPort; ++port) {
            if (abort) break;

            QTcpSocket socket;
            socket.connectToHost(target, port);

            // 设置连接超时
            if (socket.waitForConnected(500)) {
                QString service = detectService(socket, port);
                QString title = "";

                if (service == "http" || service == "https") {
                    title = fetchHttpTitle(port);
                }

                emit portFound(port, service, title);
                socket.disconnectFromHost();
            }

            scanned++;
            emit scanProgress((scanned * 100) / totalPorts);
        }

        emit scanFinished();
    }

private:
    QString detectService(QTcpSocket &socket, int port) {
        // 常见服务识别
        if (port == 80) return "http";
        if (port == 443) return "https";
        if (port == 22) return "ssh";
        if (port == 8080 || port == 3128) return "proxy";
        if (port == 53) return "dns";
        if (port == 23) return "telnet";
        if (port == 21) return "ftp";

        // 尝试通过响应识别
        if (socket.waitForReadyRead(500)) {
            QByteArray response = socket.read(1024);
            if (response.contains("SSH")) return "ssh";
            if (response.contains("HTTP")) return "http";
            if (response.contains("220 FTP")) return "ftp";
            if (response.contains("DNS")) return "dns";
        }

        return "unknown";
    }

    QString fetchHttpTitle(int port) {
        QString protocol = (port == 443) ? "https" : "http";
        QUrl url(protocol + "://" + target);
        QEventLoop loop;
        QString title = "";

        QNetworkAccessManager manager;
        QNetworkRequest request(url);
        request.setRawHeader("User-Agent", "PortScanner/1.0");

        // 设置超时定时器
        QTimer timer;
        timer.setSingleShot(true);
        timer.start(3000); // 3秒超时

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

    bool abort;
    QString target;
    int startPort;
    int endPort;
};

// 主窗口类
class MainWindow : public QMainWindow {
    Q_OBJECT
public:
    MainWindow() : QMainWindow() {
        setupUI();
        scanner = new PortScanner(this);
        connectSignals();
    }

    ~MainWindow() {
        scanner->stop();
        scanner->wait();
    }

private:
    void setupUI() {
        setWindowTitle("端口扫描器");
        resize(800, 600);

        // 创建中心部件
        QWidget *centralWidget = new QWidget(this);
        setCentralWidget(centralWidget);

        // 布局
        QVBoxLayout *layout = new QVBoxLayout(centralWidget);

        // 输入区域
        QHBoxLayout *inputLayout = new QHBoxLayout();
        targetEdit = new QLineEdit("localhost", this);
        startPortEdit = new QLineEdit("1", this);
        endPortEdit = new QLineEdit("1000", this);

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

        QHBoxLayout *buttonLayout = new QHBoxLayout();
        buttonLayout->addWidget(scanButton);
        buttonLayout->addWidget(stopButton);

        // 添加进度条
        progressBar = new QProgressBar(this);
        progressBar->setRange(0, 100);
        progressBar->setTextVisible(true);
        progressBar->setFormat("扫描进度: %p%");

        // 结果表格
        resultsTable = new QTableWidget(0, 4, this);
        QStringList headers = {"端口", "服务", "状态", "标题"};
        resultsTable->setHorizontalHeaderLabels(headers);
        resultsTable->horizontalHeader()->setSectionResizeMode(3, QHeaderView::Stretch);

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

        connect(scanner, &PortScanner::portFound,
                this, &MainWindow::addScanResult);
        connect(scanner, &PortScanner::scanFinished,
                this, &MainWindow::onScanFinished);
        // 修复连接问题：使用进度条代替状态栏显示进度
        connect(scanner, &PortScanner::scanProgress,
                progressBar, &QProgressBar::setValue);
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
        statusBar()->showMessage("扫描中...");
        progressBar->setValue(0); // 重置进度条

        scanner->scan(targetEdit->text(), start, end);
    }

    void stopScan() {
        scanner->stop();
        scanButton->setEnabled(true);
        stopButton->setEnabled(false);
        statusBar()->showMessage("扫描已停止");
    }

    void addScanResult(int port, const QString &service, const QString &title) {
        int row = resultsTable->rowCount();
        resultsTable->insertRow(row);

        resultsTable->setItem(row, 0, new QTableWidgetItem(QString::number(port)));
        resultsTable->setItem(row, 1, new QTableWidgetItem(service));
        resultsTable->setItem(row, 2, new QTableWidgetItem("开放"));
        resultsTable->setItem(row, 3, new QTableWidgetItem(title));
    }

    void onScanFinished() {
        scanButton->setEnabled(true);
        stopButton->setEnabled(false);
        statusBar()->showMessage("扫描完成");
        progressBar->setValue(100);
    }

private:
    QLineEdit *targetEdit;
    QLineEdit *startPortEdit;
    QLineEdit *endPortEdit;
    QPushButton *scanButton;
    QPushButton *stopButton;
    QProgressBar *progressBar; // 添加进度条
    QTableWidget *resultsTable;
    PortScanner *scanner;
};

// 主函数
int main(int argc, char *argv[]) {
    QApplication app(argc, argv);
    MainWindow window;
    window.show();
    return app.exec();
}

#include "main.moc"
