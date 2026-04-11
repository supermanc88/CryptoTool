#include "widgets/digestpage.h"

#include "crypto/digest_service.h"
#include "widgets/pagechrome.h"

#include <QComboBox>
#include <QFrame>
#include <QHBoxLayout>
#include <QLabel>
#include <QPushButton>
#include <QScrollArea>
#include <QVBoxLayout>

using namespace WidgetChrome;

DigestPage::DigestPage(QWidget *parent)
    : QWidget(parent)
    , digestCombo_(nullptr)
    , plainEdit_(nullptr)
    , resultEdit_(nullptr)
    , statusChip_(nullptr)
{
    buildUi();
}

void DigestPage::buildUi()
{
    auto *scroll = new QScrollArea(this);
    scroll->setWidgetResizable(true);
    scroll->setFrameShape(QFrame::NoFrame);

    auto *canvas = new QWidget(scroll);
    auto *root = new QVBoxLayout(canvas);
    root->setContentsMargins(28, 28, 28, 28);
    root->setSpacing(22);

    auto *hero = new QFrame(canvas);
    hero->setObjectName("digestHero");
    auto *heroLayout = new QVBoxLayout(hero);
    heroLayout->setContentsMargins(28, 28, 28, 28);
    heroLayout->setSpacing(10);

    auto *heroTop = new QHBoxLayout;
    auto *heroKicker = new QLabel("Digest Workspace", hero);
    heroKicker->setProperty("role", "hero-kicker");
    statusChip_ = new QLabel("Ready", hero);
    statusChip_->setObjectName("digestStatusChip");
    heroTop->addWidget(heroKicker);
    heroTop->addStretch();
    heroTop->addWidget(statusChip_);

    auto *heroTitle = new QLabel("摘要计算回到最直接的单任务界面", hero);
    heroTitle->setProperty("role", "hero-title");
    auto *heroBody = new QLabel("摘要算法选择、输入原文、输出结果三段式布局，适合高频试算。", hero);
    heroBody->setProperty("role", "hero-body");
    heroBody->setWordWrap(true);

    heroLayout->addLayout(heroTop);
    heroLayout->addWidget(heroTitle);
    heroLayout->addWidget(heroBody);
    root->addWidget(hero);

    digestCombo_ = new QComboBox;
    digestCombo_->addItems({"md4", "md5", "mdc2", "sha1", "sha224", "sha256", "sha3-224", "sha3-256",
                            "sha3-384", "sha3-512", "sha384", "sha512", "sha512-224", "sha512-256",
                            "sm3", "blake2b512", "blake2s256", "shake128", "shake256"});
    plainEdit_ = createEditor("Input hex", false, 180);
    resultEdit_ = createEditor("Digest output", true, 180);

    auto *configLayout = new QVBoxLayout;
    configLayout->addWidget(createSectionLabel("Digest Algorithm"));
    configLayout->addWidget(digestCombo_);

    auto *workLayout = new QVBoxLayout;
    auto *actionRow = new QHBoxLayout;
    auto *calcButton = createActionButton("Calculate Digest");
    auto *sendButton = createActionButton("Send Result to Converter", "secondary");
    auto *clearButton = createActionButton("Clear Workspace", "ghost");
    actionRow->addWidget(calcButton);
    actionRow->addWidget(sendButton);
    actionRow->addStretch();
    actionRow->addWidget(clearButton);
    workLayout->addLayout(actionRow);
    workLayout->addWidget(createSectionLabel("Input"));
    workLayout->addWidget(plainEdit_);
    workLayout->addWidget(createSectionLabel("Result"));
    workLayout->addWidget(resultEdit_);

    root->addWidget(createPanel("digestPanel", "CONFIG", "Digest Selection", "算法选择从输入区独立出来，切换不同摘要时更明确。", configLayout));
    root->addWidget(createPanel("digestPanel", "WORKFLOW", "Input & Result", "集中处理一次摘要计算的全部上下文。", workLayout));
    root->addStretch();

    scroll->setWidget(canvas);
    auto *pageLayout = new QVBoxLayout(this);
    pageLayout->setContentsMargins(0, 0, 0, 0);
    pageLayout->addWidget(scroll);

    setStyleSheet(R"(
        QFrame#digestHero { background: qlineargradient(x1:0, y1:0, x2:1, y2:1, stop:0 #124559, stop:0.55 #598392, stop:1 #aec3b0); border-radius: 28px; }
        QFrame#digestPanel { background: #fffdfa; border: 1px solid #d8d2c7; border-radius: 22px; }
        QLabel[role="hero-kicker"] { color: rgba(255,255,255,0.72); font-size: 12px; font-weight: 700; letter-spacing: 1px; }
        QLabel[role="hero-title"] { color: white; font-size: 32px; font-weight: 800; }
        QLabel[role="hero-body"] { color: rgba(255,255,255,0.84); font-size: 14px; }
        QLabel#digestStatusChip { background: rgba(255,255,255,0.16); color: white; border: 1px solid rgba(255,255,255,0.28); border-radius: 999px; padding: 7px 12px; font-weight: 700; }
        QLabel[role="eyebrow"] { color: #5d806f; font-size: 11px; font-weight: 800; letter-spacing: 1px; }
        QLabel[role="panel-title"] { color: #20170f; font-size: 24px; font-weight: 800; }
        QLabel[role="panel-description"] { color: #746553; font-size: 13px; }
        QLabel[role="field-label"] { color: #3a2d22; font-size: 12px; font-weight: 700; }
        QTextEdit, QComboBox { background: #fffefd; border: 1px solid #d8cbb9; border-radius: 16px; padding: 12px 14px; color: #241a12; }
        QComboBox { min-height: 36px; }
        QPushButton { border-radius: 12px; padding: 11px 16px; font-weight: 700; border: none; }
        QPushButton[variant="primary"] { background: #598392; color: white; }
        QPushButton[variant="primary"]:hover { background: #496c78; }
        QPushButton[variant="secondary"] { background: #deebe7; color: #2d5d4e; }
        QPushButton[variant="secondary"]:hover { background: #d0e3dc; }
        QPushButton[variant="ghost"] { background: #f4efe7; color: #54483c; }
        QPushButton[variant="ghost"]:hover { background: #ece4d8; }
    )");

    connect(calcButton, &QPushButton::clicked, this, &DigestPage::handleCalculate);
    connect(sendButton, &QPushButton::clicked, this, &DigestPage::handleSendToConverter);
    connect(clearButton, &QPushButton::clicked, this, &DigestPage::handleClear);
}

void DigestPage::setStatus(const QString &message, bool success)
{
    applyStatusChip(statusChip_, message, success);
    emit statusMessageRequested(message, success);
}

void DigestPage::handleCalculate()
{
    const auto result = Crypto::DigestService::calculate(digestCombo_->currentText(), plainEdit_->toPlainText());
    if (!result.success) {
        setStatus(result.message, false);
        return;
    }

    resultEdit_->setText(result.primaryText);
    setStatus("Digest calculated.", true);
}

void DigestPage::handleClear()
{
    plainEdit_->clear();
    resultEdit_->clear();
    setStatus("Digest workspace cleared.", true);
}

void DigestPage::handleSendToConverter()
{
    if (resultEdit_->toPlainText().isEmpty()) {
        setStatus("No digest result to send.", false);
        return;
    }

    emit sendToConverterRequested(resultEdit_->toPlainText(), "Hex", "Digest result");
}
