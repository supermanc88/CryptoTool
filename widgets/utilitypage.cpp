#include "widgets/utilitypage.h"

#include "crypto/utility_service.h"
#include "widgets/pagechrome.h"

#include <QFrame>
#include <QHBoxLayout>
#include <QLabel>
#include <QPushButton>
#include <QScrollArea>
#include <QVBoxLayout>

using namespace WidgetChrome;

UtilityPage::UtilityPage(QWidget *parent)
    : QWidget(parent)
    , inputAEdit_(nullptr)
    , inputBEdit_(nullptr)
    , resultEdit_(nullptr)
    , statusChip_(nullptr)
{
    buildUi();
}

void UtilityPage::buildUi()
{
    auto *scroll = new QScrollArea(this);
    scroll->setWidgetResizable(true);
    scroll->setFrameShape(QFrame::NoFrame);

    auto *canvas = new QWidget(scroll);
    auto *root = new QVBoxLayout(canvas);
    root->setContentsMargins(28, 28, 28, 28);
    root->setSpacing(22);

    auto *hero = new QFrame(canvas);
    hero->setObjectName("utilityHero");
    auto *heroLayout = new QVBoxLayout(hero);
    heroLayout->setContentsMargins(28, 28, 28, 28);
    heroLayout->setSpacing(10);

    auto *heroTop = new QHBoxLayout;
    auto *heroKicker = new QLabel("Utility Workspace", hero);
    heroKicker->setProperty("role", "hero-kicker");
    statusChip_ = new QLabel("Ready", hero);
    statusChip_->setObjectName("utilityStatusChip");
    heroTop->addWidget(heroKicker);
    heroTop->addStretch();
    heroTop->addWidget(statusChip_);

    auto *heroTitle = new QLabel("小工具也换成完整页面", hero);
    heroTitle->setProperty("role", "hero-title");
    auto *heroBody = new QLabel("先把 XOR 计算独立成一张清晰卡片，后续再加其它 helper 也有位置。", hero);
    heroBody->setProperty("role", "hero-body");
    heroBody->setWordWrap(true);

    heroLayout->addLayout(heroTop);
    heroLayout->addWidget(heroTitle);
    heroLayout->addWidget(heroBody);
    root->addWidget(hero);

    inputAEdit_ = createEditor("Input A hex", false, 130);
    inputBEdit_ = createEditor("Input B hex", false, 130);
    resultEdit_ = createEditor("Result", true, 130);

    auto *workLayout = new QVBoxLayout;
    auto *actionRow = new QHBoxLayout;
    auto *xorButton = createActionButton("Calculate XOR");
    auto *sendButton = createActionButton("Send Result to Converter", "secondary");
    auto *clearButton = createActionButton("Clear Workspace", "ghost");
    actionRow->addWidget(xorButton);
    actionRow->addWidget(sendButton);
    actionRow->addStretch();
    actionRow->addWidget(clearButton);
    workLayout->addLayout(actionRow);
    workLayout->addWidget(createSectionLabel("Input A"));
    workLayout->addWidget(inputAEdit_);
    workLayout->addWidget(createSectionLabel("Input B"));
    workLayout->addWidget(inputBEdit_);
    workLayout->addWidget(createSectionLabel("Result"));
    workLayout->addWidget(resultEdit_);

    root->addWidget(createPanel("utilityPanel", "XOR", "Bitwise Calculator", "把异或计算做成真正的工具页，不再挤在旧 tab 角落里。", workLayout));
    root->addStretch();

    scroll->setWidget(canvas);
    auto *pageLayout = new QVBoxLayout(this);
    pageLayout->setContentsMargins(0, 0, 0, 0);
    pageLayout->addWidget(scroll);

    setStyleSheet(R"(
        QFrame#utilityHero { background: qlineargradient(x1:0, y1:0, x2:1, y2:1, stop:0 #2d3142, stop:0.55 #4f5d75, stop:1 #bfc0c0); border-radius: 28px; }
        QFrame#utilityPanel { background: #fffdfa; border: 1px solid #d8d2c7; border-radius: 22px; }
        QLabel[role="hero-kicker"] { color: rgba(255,255,255,0.72); font-size: 12px; font-weight: 700; letter-spacing: 1px; }
        QLabel[role="hero-title"] { color: white; font-size: 32px; font-weight: 800; }
        QLabel[role="hero-body"] { color: rgba(255,255,255,0.84); font-size: 14px; }
        QLabel#utilityStatusChip { background: rgba(255,255,255,0.16); color: white; border: 1px solid rgba(255,255,255,0.28); border-radius: 999px; padding: 7px 12px; font-weight: 700; }
        QLabel[role="eyebrow"] { color: #6a7383; font-size: 11px; font-weight: 800; letter-spacing: 1px; }
        QLabel[role="panel-title"] { color: #20170f; font-size: 24px; font-weight: 800; }
        QLabel[role="panel-description"] { color: #746553; font-size: 13px; }
        QLabel[role="field-label"] { color: #3a2d22; font-size: 12px; font-weight: 700; }
        QTextEdit { background: #fffefd; border: 1px solid #d8cbb9; border-radius: 16px; padding: 12px 14px; color: #241a12; }
        QPushButton { border-radius: 12px; padding: 11px 16px; font-weight: 700; border: none; }
        QPushButton[variant="primary"] { background: #4f5d75; color: white; }
        QPushButton[variant="primary"]:hover { background: #414d62; }
        QPushButton[variant="secondary"] { background: #e4e8ec; color: #3b4452; }
        QPushButton[variant="secondary"]:hover { background: #d7dee5; }
        QPushButton[variant="ghost"] { background: #f4efe7; color: #54483c; }
        QPushButton[variant="ghost"]:hover { background: #ece4d8; }
    )");

    connect(xorButton, &QPushButton::clicked, this, &UtilityPage::handleXor);
    connect(sendButton, &QPushButton::clicked, this, &UtilityPage::handleSendToConverter);
    connect(clearButton, &QPushButton::clicked, this, &UtilityPage::handleClear);
}

void UtilityPage::setStatus(const QString &message, bool success)
{
    applyStatusChip(statusChip_, message, success);
    emit statusMessageRequested(message, success);
}

void UtilityPage::handleXor()
{
    const auto result = Crypto::UtilityService::xorHex(inputAEdit_->toPlainText(), inputBEdit_->toPlainText());
    if (!result.success) {
        setStatus(result.message, false);
        return;
    }

    resultEdit_->setText(result.primaryText);
    setStatus("XOR calculation completed.", true);
}

void UtilityPage::handleClear()
{
    inputAEdit_->clear();
    inputBEdit_->clear();
    resultEdit_->clear();
    setStatus("Utility workspace cleared.", true);
}

void UtilityPage::handleSendToConverter()
{
    if (resultEdit_->toPlainText().isEmpty()) {
        setStatus("No XOR result to send.", false);
        return;
    }

    emit sendToConverterRequested(resultEdit_->toPlainText(), "Hex", "XOR result");
}
