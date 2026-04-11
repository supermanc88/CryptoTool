#include "mainwindow.h"

#include "widgets/convertersidepanel.h"
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
#include <QPushButton>
#include <QScrollArea>
#include <QStackedWidget>
#include <QStatusBar>
#include <QVBoxLayout>
#include <QVector>
#include <QWidget>

MainWindow::MainWindow(QWidget *parent)
    : QMainWindow(parent)
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
    , converterPanel_(nullptr)
    , converterToggleButton_(nullptr)
{
    setupWindowShell();
    applyWindowStyle();
    showStatus("CryptoTool ready.");
}

MainWindow::~MainWindow()
= default;

void MainWindow::setupWindowShell()
{
    resize(1440, 920);
    setMinimumSize(1180, 760);

    auto *central = new QWidget(this);
    setCentralWidget(central);
    setStatusBar(new QStatusBar(this));

    const QVector<QString> pages = {
        "SM2", "SM3", "SM4", "RSA", "DSA", "digest", "MAC", "Stream", "其它工具"
    };

    auto *rootLayout = new QHBoxLayout(central);
    rootLayout->setContentsMargins(24, 24, 24, 24);
    rootLayout->setSpacing(20);

    auto *navCard = new QFrame(central);
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

    auto *contentCard = new QFrame(central);
    contentCard->setObjectName("contentCard");
    auto *contentLayout = new QVBoxLayout(contentCard);
    contentLayout->setContentsMargins(18, 18, 18, 18);
    contentLayout->setSpacing(14);

    auto *contentHeader = new QHBoxLayout;
    auto *contentTitleWrap = new QVBoxLayout;
    contentTitleWrap->setSpacing(2);
    auto *contentTitle = new QLabel("Algorithm Workspace", contentCard);
    contentTitle->setObjectName("contentTitle");
    auto *contentSubtitle = new QLabel("Use the converter only for explicit data representation work.", contentCard);
    contentSubtitle->setObjectName("contentSubtitle");
    contentSubtitle->setWordWrap(true);
    contentTitleWrap->addWidget(contentTitle);
    contentTitleWrap->addWidget(contentSubtitle);
    converterToggleButton_ = new QPushButton("Open Converter", contentCard);
    converterToggleButton_->setObjectName("converterToggleButton");
    converterToggleButton_->setCheckable(true);
    contentHeader->addLayout(contentTitleWrap, 1);
    contentHeader->addWidget(converterToggleButton_);
    contentLayout->addLayout(contentHeader);

    auto *workspaceLayout = new QHBoxLayout;
    workspaceLayout->setSpacing(16);

    pageStack_ = new QStackedWidget(contentCard);
    pageStack_->setObjectName("pageStack");
    workspaceLayout->addWidget(pageStack_, 1);

    converterPanel_ = new ConverterSidePanel(contentCard);
    converterPanel_->setMinimumWidth(320);
    converterPanel_->setMaximumWidth(360);
    converterPanel_->hide();
    connect(converterPanel_, &ConverterSidePanel::statusMessageRequested, this, &MainWindow::showStatus);
    workspaceLayout->addWidget(converterPanel_);
    contentLayout->addLayout(workspaceLayout, 1);

    rootLayout->addWidget(navCard);
    rootLayout->addWidget(contentCard, 1);

    for (const auto &pageTitle : pages) {
        navigationList_->addItem(pageTitle);
        auto *scrollArea = new QScrollArea(pageStack_);
        scrollArea->setWidgetResizable(true);
        scrollArea->setFrameShape(QFrame::NoFrame);

        if (pageTitle == "SM2") {
            sm2Page_ = new Sm2Page(scrollArea);
            connect(sm2Page_, &Sm2Page::statusMessageRequested, this, &MainWindow::showStatus);
            scrollArea->setWidget(sm2Page_);
        } else if (pageTitle == "SM3") {
            sm3Page_ = new Sm3Page(scrollArea);
            connect(sm3Page_, &Sm3Page::statusMessageRequested, this, &MainWindow::showStatus);
            connect(sm3Page_, &Sm3Page::sendToConverterRequested, this, &MainWindow::loadConverterSource);
            scrollArea->setWidget(sm3Page_);
        } else if (pageTitle == "SM4") {
            sm4Page_ = new Sm4Page(scrollArea);
            connect(sm4Page_, &Sm4Page::statusMessageRequested, this, &MainWindow::showStatus);
            connect(sm4Page_, &Sm4Page::sendToConverterRequested, this, &MainWindow::loadConverterSource);
            scrollArea->setWidget(sm4Page_);
        } else if (pageTitle == "RSA") {
            rsaPage_ = new RsaPage(scrollArea);
            connect(rsaPage_, &RsaPage::statusMessageRequested, this, &MainWindow::showStatus);
            scrollArea->setWidget(rsaPage_);
        } else if (pageTitle == "DSA") {
            dsaPage_ = new DsaPage(scrollArea);
            connect(dsaPage_, &DsaPage::statusMessageRequested, this, &MainWindow::showStatus);
            scrollArea->setWidget(dsaPage_);
        } else if (pageTitle == "digest") {
            digestPage_ = new DigestPage(scrollArea);
            connect(digestPage_, &DigestPage::statusMessageRequested, this, &MainWindow::showStatus);
            connect(digestPage_, &DigestPage::sendToConverterRequested, this, &MainWindow::loadConverterSource);
            scrollArea->setWidget(digestPage_);
        } else if (pageTitle == "MAC") {
            macPage_ = new MacPage(scrollArea);
            connect(macPage_, &MacPage::statusMessageRequested, this, &MainWindow::showStatus);
            connect(macPage_, &MacPage::sendToConverterRequested, this, &MainWindow::loadConverterSource);
            scrollArea->setWidget(macPage_);
        } else if (pageTitle == "Stream") {
            streamPage_ = new StreamPage(scrollArea);
            connect(streamPage_, &StreamPage::statusMessageRequested, this, &MainWindow::showStatus);
            connect(streamPage_, &StreamPage::sendToConverterRequested, this, &MainWindow::loadConverterSource);
            scrollArea->setWidget(streamPage_);
        } else if (pageTitle == "其它工具") {
            utilityPage_ = new UtilityPage(scrollArea);
            connect(utilityPage_, &UtilityPage::statusMessageRequested, this, &MainWindow::showStatus);
            connect(utilityPage_, &UtilityPage::sendToConverterRequested, this, &MainWindow::loadConverterSource);
            scrollArea->setWidget(utilityPage_);
        }

        pageStack_->addWidget(scrollArea);
    }

    connect(navigationList_, &QListWidget::currentRowChanged, pageStack_, &QStackedWidget::setCurrentIndex);
    connect(converterToggleButton_, &QPushButton::toggled, this, &MainWindow::setConverterVisible);
    navigationList_->setCurrentRow(0);
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
        QLabel#contentTitle {
            color: #2b2217;
            font-size: 24px;
            font-weight: 700;
        }
        QLabel#contentSubtitle {
            color: #776955;
            font-size: 12px;
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
        QPushButton#converterToggleButton {
            background: #e7f0ed;
            color: #17483e;
            border: none;
            border-radius: 12px;
            padding: 10px 14px;
            font-weight: 700;
        }
        QPushButton#converterToggleButton:checked {
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

void MainWindow::setConverterVisible(bool visible)
{
    if (!converterPanel_ || !converterToggleButton_) {
        return;
    }

    converterPanel_->setVisible(visible);
    converterToggleButton_->setText(visible ? "Hide Converter" : "Open Converter");
}

void MainWindow::loadConverterSource(const QString &text, const QString &sourceFormat, const QString &label)
{
    if (!converterPanel_) {
        return;
    }

    if (!converterToggleButton_->isChecked()) {
        converterToggleButton_->setChecked(true);
    }
    converterPanel_->loadSource(text, sourceFormat, label);
}
