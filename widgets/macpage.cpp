#include "widgets/macpage.h"

#include "crypto/mac_service.h"
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

MacPage::MacPage(QWidget *parent)
    : QWidget(parent)
    , macModeCombo_(nullptr)
    , internalModeCombo_(nullptr)
    , keyEdit_(nullptr)
    , plainEdit_(nullptr)
    , resultEdit_(nullptr)
    , statusChip_(nullptr)
{
    buildUi();
    refreshInternalModes();
}

void MacPage::buildUi()
{
    auto *scroll = new QScrollArea(this);
    scroll->setWidgetResizable(true);
    scroll->setFrameShape(QFrame::NoFrame);

    auto *canvas = new QWidget(scroll);
    auto *root = new QVBoxLayout(canvas);
    root->setContentsMargins(28, 28, 28, 28);
    root->setSpacing(22);

    auto *hero = new QFrame(canvas);
    hero->setObjectName("macHero");
    auto *heroLayout = new QVBoxLayout(hero);
    heroLayout->setContentsMargins(28, 28, 28, 28);
    heroLayout->setSpacing(10);

    auto *heroTop = new QHBoxLayout;
    auto *heroKicker = new QLabel("MAC Workspace", hero);
    heroKicker->setProperty("role", "hero-kicker");
    statusChip_ = new QLabel("Ready", hero);
    statusChip_->setObjectName("macStatusChip");
    heroTop->addWidget(heroKicker);
    heroTop->addStretch();
    heroTop->addWidget(statusChip_);

    auto *heroTitle = new QLabel("模式选择和内部算法联动展示", hero);
    heroTitle->setProperty("role", "hero-title");
    auto *heroBody = new QLabel("HMAC、GMAC、CMAC 分开看，内部算法联动刷新，不再挤在旧表单一层里。", hero);
    heroBody->setProperty("role", "hero-body");
    heroBody->setWordWrap(true);

    heroLayout->addLayout(heroTop);
    heroLayout->addWidget(heroTitle);
    heroLayout->addWidget(heroBody);
    root->addWidget(hero);

    macModeCombo_ = new QComboBox;
    macModeCombo_->addItems({"HMAC", "GMAC", "CMAC"});
    internalModeCombo_ = new QComboBox;
    keyEdit_ = createEditor("Key hex", false, 120);
    plainEdit_ = createEditor("Input hex", false, 180);
    resultEdit_ = createEditor("MAC output", true, 180);

    auto *grid = new QGridLayout;
    grid->setHorizontalSpacing(18);
    grid->setVerticalSpacing(18);

    auto *configLayout = new QVBoxLayout;
    configLayout->addWidget(createSectionLabel("MAC Mode"));
    configLayout->addWidget(macModeCombo_);
    configLayout->addWidget(createSectionLabel("Internal Algorithm"));
    configLayout->addWidget(internalModeCombo_);
    configLayout->addWidget(createSectionLabel("Key"));
    configLayout->addWidget(keyEdit_);
    grid->addWidget(createPanel("macPanel", "CONFIG", "Mode & Key", "模式和内部算法拆开展示，参数关系更清楚。", configLayout), 0, 0);

    auto *workLayout = new QVBoxLayout;
    auto *actionRow = new QHBoxLayout;
    auto *calcButton = createActionButton("Calculate MAC");
    auto *clearButton = createActionButton("Clear Workspace", "ghost");
    actionRow->addWidget(calcButton);
    actionRow->addStretch();
    actionRow->addWidget(clearButton);
    workLayout->addLayout(actionRow);
    workLayout->addWidget(createSectionLabel("Input"));
    workLayout->addWidget(plainEdit_);
    workLayout->addWidget(createSectionLabel("Result"));
    workLayout->addWidget(resultEdit_);
    grid->addWidget(createPanel("macPanel", "WORKFLOW", "Input & Output", "专门留给原文和 MAC 结果的工作区。", workLayout), 0, 1);

    grid->setColumnStretch(0, 4);
    grid->setColumnStretch(1, 5);
    root->addLayout(grid);
    root->addStretch();

    scroll->setWidget(canvas);
    auto *pageLayout = new QVBoxLayout(this);
    pageLayout->setContentsMargins(0, 0, 0, 0);
    pageLayout->addWidget(scroll);

    setStyleSheet(R"(
        QFrame#macHero { background: qlineargradient(x1:0, y1:0, x2:1, y2:1, stop:0 #4a2c2a, stop:0.55 #8c5e58, stop:1 #d7b49e); border-radius: 28px; }
        QFrame#macPanel { background: #fffdfa; border: 1px solid #d8d2c7; border-radius: 22px; }
        QLabel[role="hero-kicker"] { color: rgba(255,255,255,0.72); font-size: 12px; font-weight: 700; letter-spacing: 1px; }
        QLabel[role="hero-title"] { color: white; font-size: 32px; font-weight: 800; }
        QLabel[role="hero-body"] { color: rgba(255,255,255,0.84); font-size: 14px; }
        QLabel#macStatusChip { background: rgba(255,255,255,0.16); color: white; border: 1px solid rgba(255,255,255,0.28); border-radius: 999px; padding: 7px 12px; font-weight: 700; }
        QLabel[role="eyebrow"] { color: #9f6b5e; font-size: 11px; font-weight: 800; letter-spacing: 1px; }
        QLabel[role="panel-title"] { color: #20170f; font-size: 24px; font-weight: 800; }
        QLabel[role="panel-description"] { color: #746553; font-size: 13px; }
        QLabel[role="field-label"] { color: #3a2d22; font-size: 12px; font-weight: 700; }
        QTextEdit, QComboBox { background: #fffefd; border: 1px solid #d8cbb9; border-radius: 16px; padding: 12px 14px; color: #241a12; }
        QComboBox { min-height: 36px; }
        QPushButton { border-radius: 12px; padding: 11px 16px; font-weight: 700; border: none; }
        QPushButton[variant="primary"] { background: #8c5e58; color: white; }
        QPushButton[variant="primary"]:hover { background: #744c47; }
        QPushButton[variant="ghost"] { background: #f4efe7; color: #54483c; }
        QPushButton[variant="ghost"]:hover { background: #ece4d8; }
    )");

    connect(calcButton, &QPushButton::clicked, this, &MacPage::handleCalculate);
    connect(clearButton, &QPushButton::clicked, this, &MacPage::handleClear);
    connect(macModeCombo_, qOverload<int>(&QComboBox::currentIndexChanged), this, &MacPage::handleModeChanged);
}

void MacPage::setStatus(const QString &message, bool success)
{
    applyStatusChip(statusChip_, message, success);
    emit statusMessageRequested(message, success);
}

void MacPage::refreshInternalModes()
{
    const QString currentMode = macModeCombo_->currentText();
    const QStringList modes = Crypto::MacService::internalModes(currentMode);
    internalModeCombo_->clear();
    internalModeCombo_->addItems(modes);
}

void MacPage::handleCalculate()
{
    const auto result = Crypto::MacService::calculate(macModeCombo_->currentText(),
                                                      internalModeCombo_->currentText(),
                                                      keyEdit_->toPlainText(),
                                                      plainEdit_->toPlainText());
    if (!result.success) {
        setStatus(result.message, false);
        return;
    }

    resultEdit_->setText(result.primaryText);
    setStatus("MAC calculated.", true);
}

void MacPage::handleModeChanged(int index)
{
    Q_UNUSED(index);
    refreshInternalModes();
}

void MacPage::handleClear()
{
    keyEdit_->clear();
    plainEdit_->clear();
    resultEdit_->clear();
    setStatus("MAC workspace cleared.", true);
}
