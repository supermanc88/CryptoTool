#include "widgets/streampage.h"

#include "crypto/stream_service.h"
#include "widgets/pagechrome.h"

#include <QComboBox>
#include <QFrame>
#include <QGridLayout>
#include <QHBoxLayout>
#include <QLabel>
#include <QPushButton>
#include <QScrollArea>
#include <QVBoxLayout>

using namespace WidgetChrome;

StreamPage::StreamPage(QWidget *parent)
    : QWidget(parent)
    , modeCombo_(nullptr)
    , keyEdit_(nullptr)
    , ivEdit_(nullptr)
    , inputEdit_(nullptr)
    , resultEdit_(nullptr)
    , statusChip_(nullptr)
{
    buildUi();
}

void StreamPage::buildUi()
{
    auto *scroll = new QScrollArea(this);
    scroll->setWidgetResizable(true);
    scroll->setFrameShape(QFrame::NoFrame);

    auto *canvas = new QWidget(scroll);
    auto *root = new QVBoxLayout(canvas);
    root->setContentsMargins(28, 28, 28, 28);
    root->setSpacing(22);

    auto *hero = new QFrame(canvas);
    hero->setObjectName("streamHero");
    auto *heroLayout = new QVBoxLayout(hero);
    heroLayout->setContentsMargins(28, 28, 28, 28);
    heroLayout->setSpacing(10);

    auto *heroTop = new QHBoxLayout;
    auto *heroKicker = new QLabel("Stream Workspace", hero);
    heroKicker->setProperty("role", "hero-kicker");
    statusChip_ = new QLabel("Ready", hero);
    statusChip_->setObjectName("streamStatusChip");
    heroTop->addWidget(heroKicker);
    heroTop->addStretch();
    heroTop->addWidget(statusChip_);

    auto *heroTitle = new QLabel("流密码页收敛成轻量工作台", hero);
    heroTitle->setProperty("role", "hero-title");
    auto *heroBody = new QLabel("模式、密钥、IV 在左侧，输入输出在右侧，适合快速验证 RC4 或 ChaCha20。", hero);
    heroBody->setProperty("role", "hero-body");
    heroBody->setWordWrap(true);

    heroLayout->addLayout(heroTop);
    heroLayout->addWidget(heroTitle);
    heroLayout->addWidget(heroBody);
    root->addWidget(hero);

    modeCombo_ = new QComboBox;
    modeCombo_->addItems({"rc4", "chacha20"});
    keyEdit_ = createEditor("Key hex", false, 120);
    ivEdit_ = createEditor("IV / nonce hex", false, 120);
    inputEdit_ = createEditor("Input hex", false, 220);
    resultEdit_ = createEditor("Output hex", true, 220);

    auto *grid = new QGridLayout;
    grid->setHorizontalSpacing(18);
    grid->setVerticalSpacing(18);

    auto *configLayout = new QVBoxLayout;
    configLayout->addWidget(createSectionLabel("Mode"));
    configLayout->addWidget(modeCombo_);
    configLayout->addWidget(createSectionLabel("Key"));
    configLayout->addWidget(keyEdit_);
    configLayout->addWidget(createSectionLabel("IV / Nonce"));
    configLayout->addWidget(ivEdit_);
    grid->addWidget(createPanel("streamPanel", "CONFIG", "Cipher Setup", "把模式与材料集中管理，切换算法时更稳定。", configLayout), 0, 0);

    auto *workLayout = new QVBoxLayout;
    auto *actionRow = new QHBoxLayout;
    auto *encryptButton = createActionButton("Encrypt");
    auto *decryptButton = createActionButton("Decrypt", "secondary");
    auto *clearButton = createActionButton("Clear Workspace", "ghost");
    actionRow->addWidget(encryptButton);
    actionRow->addWidget(decryptButton);
    actionRow->addStretch();
    actionRow->addWidget(clearButton);
    workLayout->addLayout(actionRow);
    workLayout->addWidget(createSectionLabel("Input"));
    workLayout->addWidget(inputEdit_);
    workLayout->addWidget(createSectionLabel("Output"));
    workLayout->addWidget(resultEdit_);
    grid->addWidget(createPanel("streamPanel", "WORKFLOW", "Encrypt / Decrypt", "右侧保留主要工作区，输入和输出不再分散。", workLayout), 0, 1);

    grid->setColumnStretch(0, 4);
    grid->setColumnStretch(1, 5);
    root->addLayout(grid);
    root->addStretch();

    scroll->setWidget(canvas);
    auto *pageLayout = new QVBoxLayout(this);
    pageLayout->setContentsMargins(0, 0, 0, 0);
    pageLayout->addWidget(scroll);

    setStyleSheet(R"(
        QFrame#streamHero { background: qlineargradient(x1:0, y1:0, x2:1, y2:1, stop:0 #243b53, stop:0.55 #486581, stop:1 #9fb3c8); border-radius: 28px; }
        QFrame#streamPanel { background: #fffdfa; border: 1px solid #d8d2c7; border-radius: 22px; }
        QLabel[role="hero-kicker"] { color: rgba(255,255,255,0.72); font-size: 12px; font-weight: 700; letter-spacing: 1px; }
        QLabel[role="hero-title"] { color: white; font-size: 32px; font-weight: 800; }
        QLabel[role="hero-body"] { color: rgba(255,255,255,0.84); font-size: 14px; }
        QLabel#streamStatusChip { background: rgba(255,255,255,0.16); color: white; border: 1px solid rgba(255,255,255,0.28); border-radius: 999px; padding: 7px 12px; font-weight: 700; }
        QLabel[role="eyebrow"] { color: #5a7590; font-size: 11px; font-weight: 800; letter-spacing: 1px; }
        QLabel[role="panel-title"] { color: #20170f; font-size: 24px; font-weight: 800; }
        QLabel[role="panel-description"] { color: #746553; font-size: 13px; }
        QLabel[role="field-label"] { color: #3a2d22; font-size: 12px; font-weight: 700; }
        QTextEdit, QComboBox { background: #fffefd; border: 1px solid #d8cbb9; border-radius: 16px; padding: 12px 14px; color: #241a12; }
        QComboBox { min-height: 36px; }
        QPushButton { border-radius: 12px; padding: 11px 16px; font-weight: 700; border: none; }
        QPushButton[variant="primary"] { background: #486581; color: white; }
        QPushButton[variant="primary"]:hover { background: #3b5269; }
        QPushButton[variant="secondary"] { background: #dfe8ef; color: #264158; }
        QPushButton[variant="secondary"]:hover { background: #d3e0e9; }
        QPushButton[variant="ghost"] { background: #f4efe7; color: #54483c; }
        QPushButton[variant="ghost"]:hover { background: #ece4d8; }
    )");

    connect(encryptButton, &QPushButton::clicked, this, &StreamPage::handleEncrypt);
    connect(decryptButton, &QPushButton::clicked, this, &StreamPage::handleDecrypt);
    connect(clearButton, &QPushButton::clicked, this, &StreamPage::handleClear);
}

void StreamPage::setStatus(const QString &message, bool success)
{
    applyStatusChip(statusChip_, message, success);
    emit statusMessageRequested(message, success);
}

void StreamPage::handleEncrypt()
{
    const auto result = Crypto::StreamService::process(modeCombo_->currentText(),
                                                       keyEdit_->toPlainText(),
                                                       inputEdit_->toPlainText(),
                                                       ivEdit_->toPlainText(),
                                                       true);
    if (!result.success) {
        setStatus(result.message, false);
        return;
    }

    resultEdit_->setText(result.primaryText);
    setStatus("Stream encryption completed.", true);
}

void StreamPage::handleDecrypt()
{
    const auto result = Crypto::StreamService::process(modeCombo_->currentText(),
                                                       keyEdit_->toPlainText(),
                                                       inputEdit_->toPlainText(),
                                                       ivEdit_->toPlainText(),
                                                       false);
    if (!result.success) {
        setStatus(result.message, false);
        return;
    }

    resultEdit_->setText(result.primaryText);
    setStatus("Stream decryption completed.", true);
}

void StreamPage::handleClear()
{
    keyEdit_->clear();
    ivEdit_->clear();
    inputEdit_->clear();
    resultEdit_->clear();
    setStatus("Stream workspace cleared.", true);
}
