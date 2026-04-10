#include "mainwindow.h"
#include "./ui_mainwindow.h"

#include "widgets/digestpage.h"
#include "widgets/dsapage.h"
#include "widgets/macpage.h"
#include "widgets/rsapage.h"
#include "widgets/sm2page.h"
#include "widgets/sm3page.h"
#include "widgets/sm4page.h"
#include "widgets/streampage.h"
#include "widgets/utilitypage.h"

#include <QFrame>
#include <QHBoxLayout>
#include <QLabel>
#include <QListWidget>
#include <QScrollArea>
#include <QStackedWidget>
#include <QStatusBar>
#include <QTabWidget>
#include <QVBoxLayout>
#include <QVector>

MainWindow::MainWindow(QWidget *parent)
    : QMainWindow(parent)
    , ui(new Ui::MainWindow)
    , navigationList_(nullptr)
    , pageStack_(nullptr)
    , sm2Page_(nullptr)
    , sm3Page_(nullptr)
    , sm4Page_(nullptr)
    , rsaPage_(nullptr)
    , dsaPage_(nullptr)
    , digestPage_(nullptr)
    , macPage_(nullptr)
    , streamPage_(nullptr)
    , utilityPage_(nullptr)
{
    ui->setupUi(this);
    setupWindowShell();
    applyWindowStyle();
    showStatus("CryptoTool ready.");
}

MainWindow::~MainWindow()
{
    delete ui;
}

void MainWindow::setupWindowShell()
{
    resize(1440, 920);
    setMinimumSize(1180, 760);

    auto *tabWidget = ui->tabWidget_other_tool;
    QVector<QPair<QString, QWidget *>> pages;
    for (int index = tabWidget->count() - 1; index >= 0; --index) {
        QWidget *page = tabWidget->widget(index);
        const QString title = tabWidget->tabText(index);
        tabWidget->removeTab(index);
        pages.prepend({title, page});
    }

    auto *rootLayout = new QHBoxLayout(ui->centralwidget);
    rootLayout->setContentsMargins(24, 24, 24, 24);
    rootLayout->setSpacing(20);

    auto *navCard = new QFrame(ui->centralwidget);
    navCard->setObjectName("navCard");
    navCard->setMinimumWidth(250);
    auto *navLayout = new QVBoxLayout(navCard);
    navLayout->setContentsMargins(18, 18, 18, 18);
    navLayout->setSpacing(14);

    auto *appTitle = new QLabel("CryptoTool", navCard);
    appTitle->setObjectName("appTitle");
    auto *appSubtitle = new QLabel("A cleaner desktop workspace for algorithm calculation.", navCard);
    appSubtitle->setObjectName("appSubtitle");
    appSubtitle->setWordWrap(true);

    navigationList_ = new QListWidget(navCard);
    navigationList_->setObjectName("toolNavigation");
    navigationList_->setSpacing(6);

    navLayout->addWidget(appTitle);
    navLayout->addWidget(appSubtitle);
    navLayout->addWidget(navigationList_, 1);

    auto *contentCard = new QFrame(ui->centralwidget);
    contentCard->setObjectName("contentCard");
    auto *contentLayout = new QVBoxLayout(contentCard);
    contentLayout->setContentsMargins(18, 18, 18, 18);
    contentLayout->setSpacing(0);

    pageStack_ = new QStackedWidget(contentCard);
    pageStack_->setObjectName("pageStack");
    contentLayout->addWidget(pageStack_);

    rootLayout->addWidget(navCard);
    rootLayout->addWidget(contentCard, 1);

    for (const auto &pageEntry : pages) {
        navigationList_->addItem(pageEntry.first);
        auto *scrollArea = new QScrollArea(pageStack_);
        scrollArea->setWidgetResizable(true);
        scrollArea->setFrameShape(QFrame::NoFrame);

        if (pageEntry.first == "SM2") {
            sm2Page_ = new Sm2Page(scrollArea);
            connect(sm2Page_, &Sm2Page::statusMessageRequested, this, &MainWindow::showStatus);
            scrollArea->setWidget(sm2Page_);
        } else if (pageEntry.first == "SM3") {
            sm3Page_ = new Sm3Page(scrollArea);
            connect(sm3Page_, &Sm3Page::statusMessageRequested, this, &MainWindow::showStatus);
            scrollArea->setWidget(sm3Page_);
        } else if (pageEntry.first == "SM4") {
            sm4Page_ = new Sm4Page(scrollArea);
            connect(sm4Page_, &Sm4Page::statusMessageRequested, this, &MainWindow::showStatus);
            scrollArea->setWidget(sm4Page_);
        } else if (pageEntry.first == "RSA") {
            rsaPage_ = new RsaPage(scrollArea);
            connect(rsaPage_, &RsaPage::statusMessageRequested, this, &MainWindow::showStatus);
            scrollArea->setWidget(rsaPage_);
        } else if (pageEntry.first == "DSA") {
            dsaPage_ = new DsaPage(scrollArea);
            connect(dsaPage_, &DsaPage::statusMessageRequested, this, &MainWindow::showStatus);
            scrollArea->setWidget(dsaPage_);
        } else if (pageEntry.first == "digest") {
            digestPage_ = new DigestPage(scrollArea);
            connect(digestPage_, &DigestPage::statusMessageRequested, this, &MainWindow::showStatus);
            scrollArea->setWidget(digestPage_);
        } else if (pageEntry.first == "MAC") {
            macPage_ = new MacPage(scrollArea);
            connect(macPage_, &MacPage::statusMessageRequested, this, &MainWindow::showStatus);
            scrollArea->setWidget(macPage_);
        } else if (pageEntry.first == "Stream") {
            streamPage_ = new StreamPage(scrollArea);
            connect(streamPage_, &StreamPage::statusMessageRequested, this, &MainWindow::showStatus);
            scrollArea->setWidget(streamPage_);
        } else if (pageEntry.first == "其它工具") {
            utilityPage_ = new UtilityPage(scrollArea);
            connect(utilityPage_, &UtilityPage::statusMessageRequested, this, &MainWindow::showStatus);
            scrollArea->setWidget(utilityPage_);
        } else {
            scrollArea->setWidget(pageEntry.second);
            pageEntry.second->setMinimumSize(0, 0);
        }

        pageStack_->addWidget(scrollArea);
    }

    connect(navigationList_, &QListWidget::currentRowChanged, pageStack_, &QStackedWidget::setCurrentIndex);
    navigationList_->setCurrentRow(0);

    tabWidget->hide();
    tabWidget->deleteLater();
}

void MainWindow::applyWindowStyle()
{
    setStyleSheet(R"(
        QMainWindow {
            background: #f3efe7;
        }
        QFrame#navCard, QFrame#contentCard {
            background: #fffaf2;
            border: 1px solid #d7cdbd;
            border-radius: 20px;
        }
        QLabel#appTitle {
            color: #2b2217;
            font-size: 28px;
            font-weight: 700;
        }
        QLabel#appSubtitle {
            color: #6d5f4b;
            font-size: 13px;
        }
        QListWidget#toolNavigation {
            background: transparent;
            border: none;
            outline: none;
            padding: 4px;
        }
        QListWidget#toolNavigation::item {
            color: #3d3327;
            border-radius: 12px;
            padding: 12px 14px;
        }
        QListWidget#toolNavigation::item:selected {
            background: #1f6f5f;
            color: white;
        }
        QStatusBar {
            background: #fffaf2;
            color: #4f4436;
        }
    )");
}

void MainWindow::showStatus(const QString &message, bool success) const
{
    statusBar()->showMessage(message, 6000);
    statusBar()->setStyleSheet(success ? "color: #30584a;" : "color: #9a3d2d;");
}
