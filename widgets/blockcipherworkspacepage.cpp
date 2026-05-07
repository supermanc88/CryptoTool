#include "widgets/blockcipherworkspacepage.h"

#include "widgets/aespage.h"
#include "widgets/sm4page.h"

#include <QFrame>
#include <QHBoxLayout>
#include <QLabel>
#include <QPushButton>
#include <QScrollArea>
#include <QStackedWidget>
#include <QVariant>
#include <QVBoxLayout>

BlockCipherWorkspacePage::BlockCipherWorkspacePage(QWidget *parent)
    : QWidget(parent)
    , sm4SwitchButton_(nullptr)
    , aesSwitchButton_(nullptr)
    , pageStack_(nullptr)
    , sm4Page_(nullptr)
    , aesPage_(nullptr)
{
    buildUi();
}

void BlockCipherWorkspacePage::buildUi()
{
    auto *scroll = new QScrollArea(this);
    scroll->setWidgetResizable(true);
    scroll->setFrameShape(QFrame::NoFrame);

    auto *canvas = new QWidget(scroll);
    auto *root = new QVBoxLayout(canvas);
    root->setContentsMargins(28, 28, 28, 28);
    root->setSpacing(22);

    auto *hero = new QFrame(canvas);
    hero->setObjectName("blockCipherHero");
    auto *heroLayout = new QVBoxLayout(hero);
    heroLayout->setContentsMargins(28, 28, 28, 28);
    heroLayout->setSpacing(12);

    auto *heroKicker = new QLabel("Block Cipher Workspace", hero);
    heroKicker->setProperty("role", "hero-kicker");
    auto *heroTitle = new QLabel("块加密运算工作台", hero);
    heroTitle->setProperty("role", "hero-title");
    auto *heroBody = new QLabel("把 SM4 从单一算法页提升为块加密入口，并在同一个工作台中加入 AES。", hero);
    heroBody->setProperty("role", "hero-body");
    heroBody->setWordWrap(true);

    auto *switchRow = new QHBoxLayout;
    switchRow->setSpacing(10);
    sm4SwitchButton_ = new QPushButton("SM4", hero);
    sm4SwitchButton_->setObjectName("algorithmSwitch");
    sm4SwitchButton_->setCheckable(true);
    aesSwitchButton_ = new QPushButton("AES", hero);
    aesSwitchButton_->setObjectName("algorithmSwitch");
    aesSwitchButton_->setCheckable(true);
    switchRow->addWidget(sm4SwitchButton_);
    switchRow->addWidget(aesSwitchButton_);
    switchRow->addStretch();

    heroLayout->addWidget(heroKicker);
    heroLayout->addWidget(heroTitle);
    heroLayout->addWidget(heroBody);
    heroLayout->addLayout(switchRow);
    root->addWidget(hero);

    pageStack_ = new QStackedWidget(canvas);
    sm4Page_ = new Sm4Page(pageStack_);
    aesPage_ = new AesPage(pageStack_);

    pageStack_->addWidget(sm4Page_);
    pageStack_->addWidget(aesPage_);
    root->addWidget(pageStack_);
    root->addStretch();

    scroll->setWidget(canvas);
    auto *pageLayout = new QVBoxLayout(this);
    pageLayout->setContentsMargins(0, 0, 0, 0);
    pageLayout->addWidget(scroll);

    setStyleSheet(R"(
        QFrame#blockCipherHero {
            background: qlineargradient(x1:0, y1:0, x2:1, y2:1, stop:0 #2f3a25, stop:0.55 #586b3c, stop:1 #c08c3a);
            border-radius: 28px;
        }
        QLabel[role="hero-kicker"] {
            color: rgba(255,255,255,0.72);
            font-size: 12px;
            font-weight: 700;
            letter-spacing: 1px;
        }
        QLabel[role="hero-title"] {
            color: white;
            font-size: 32px;
            font-weight: 800;
        }
        QLabel[role="hero-body"] {
            color: rgba(255,255,255,0.84);
            font-size: 14px;
        }
        QPushButton#algorithmSwitch {
            background: rgba(255,255,255,0.14);
            color: white;
            border: 1px solid rgba(255,255,255,0.18);
            border-radius: 12px;
            padding: 10px 16px;
            font-weight: 700;
        }
        QPushButton#algorithmSwitch:checked {
            background: white;
            color: #2d3624;
            border: 1px solid rgba(255,255,255,0.3);
        }
    )");

    connect(sm4Page_, &Sm4Page::statusMessageRequested, this, &BlockCipherWorkspacePage::statusMessageRequested);
    connect(sm4Page_, &Sm4Page::sendToConverterRequested, this, &BlockCipherWorkspacePage::sendToConverterRequested);
    connect(aesPage_, &AesPage::statusMessageRequested, this, &BlockCipherWorkspacePage::statusMessageRequested);
    connect(aesPage_, &AesPage::sendToConverterRequested, this, &BlockCipherWorkspacePage::sendToConverterRequested);
    connect(sm4SwitchButton_, &QPushButton::clicked, this, [this]() { switchAlgorithm(0); });
    connect(aesSwitchButton_, &QPushButton::clicked, this, [this]() { switchAlgorithm(1); });

    switchAlgorithm(0);
}

void BlockCipherWorkspacePage::switchAlgorithm(int index)
{
    if (!pageStack_) {
        return;
    }

    pageStack_->setCurrentIndex(index);
    sm4SwitchButton_->setChecked(index == 0);
    aesSwitchButton_->setChecked(index == 1);
}
