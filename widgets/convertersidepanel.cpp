#include "widgets/convertersidepanel.h"

#include "shared/converter_service.h"
#include "widgets/pagechrome.h"

#include <QApplication>
#include <QClipboard>
#include <QComboBox>
#include <QFrame>
#include <QHBoxLayout>
#include <QLabel>
#include <QPushButton>
#include <QScrollArea>
#include <QVBoxLayout>

using namespace WidgetChrome;

ConverterSidePanel::ConverterSidePanel(QWidget *parent)
    : QWidget(parent)
    , statusChip_(nullptr)
    , sourceLabel_(nullptr)
    , copyOnlyLabel_(nullptr)
    , sourceFormatCombo_(nullptr)
    , targetFormatCombo_(nullptr)
    , sourceEdit_(nullptr)
    , resultEdit_(nullptr)
{
    buildUi();
}

void ConverterSidePanel::buildUi()
{
    auto *root = new QVBoxLayout(this);
    root->setContentsMargins(0, 0, 0, 0);

    auto *scroll = new QScrollArea(this);
    scroll->setWidgetResizable(true);
    scroll->setFrameShape(QFrame::NoFrame);
    root->addWidget(scroll);

    auto *canvas = new QWidget(scroll);
    auto *layout = new QVBoxLayout(canvas);
    layout->setContentsMargins(0, 0, 0, 0);
    layout->setSpacing(18);

    auto *hero = new QFrame(canvas);
    hero->setObjectName("converterHero");
    auto *heroLayout = new QVBoxLayout(hero);
    heroLayout->setContentsMargins(22, 22, 22, 22);
    heroLayout->setSpacing(10);

    auto *heroTop = new QHBoxLayout;
    auto *heroKicker = new QLabel("Converter", hero);
    heroKicker->setProperty("role", "hero-kicker");
    statusChip_ = new QLabel("Ready", hero);
    statusChip_->setObjectName("converterStatusChip");
    heroTop->addWidget(heroKicker);
    heroTop->addStretch();
    heroTop->addWidget(statusChip_);

    auto *heroTitle = new QLabel("字节表示转换工作台", hero);
    heroTitle->setProperty("role", "hero-title");
    auto *heroBody = new QLabel("手动输入或从页面显式发送数据，在这里完成 Hex、UTF-8、Base64 之间的转换。", hero);
    heroBody->setProperty("role", "hero-body");
    heroBody->setWordWrap(true);
    sourceLabel_ = new QLabel("Source: Manual input", hero);
    sourceLabel_->setProperty("role", "hero-meta");

    heroLayout->addLayout(heroTop);
    heroLayout->addWidget(heroTitle);
    heroLayout->addWidget(heroBody);
    heroLayout->addWidget(sourceLabel_);
    layout->addWidget(hero);

    sourceFormatCombo_ = new QComboBox;
    targetFormatCombo_ = new QComboBox;
    sourceFormatCombo_->addItems(ConverterService::supportedFormats());
    targetFormatCombo_->addItems(ConverterService::supportedFormats());
    sourceFormatCombo_->setCurrentText("Hex");
    targetFormatCombo_->setCurrentText("UTF-8");

    sourceEdit_ = createEditor("Paste or type source text here", false, 180);
    resultEdit_ = createEditor("Converted result", true, 180);
    copyOnlyLabel_ = new QLabel("This first version is copy-only. Converted data will not be inserted into page fields automatically.", canvas);
    copyOnlyLabel_->setProperty("role", "panel-description");
    copyOnlyLabel_->setWordWrap(true);

    auto *configLayout = new QVBoxLayout;
    configLayout->addWidget(createSectionLabel("Source Format"));
    configLayout->addWidget(sourceFormatCombo_);
    configLayout->addWidget(createSectionLabel("Target Format"));
    configLayout->addWidget(targetFormatCombo_);
    layout->addWidget(createPanel("converterPanel", "FORMATS", "Interpretation", "选择源格式和目标格式，转换过程只在侧栏内完成。", configLayout));

    auto *workLayout = new QVBoxLayout;
    auto *actionRow = new QHBoxLayout;
    auto *convertButton = createActionButton("Convert");
    auto *copyButton = createActionButton("Copy Result", "secondary");
    auto *clearButton = createActionButton("Clear", "ghost");
    actionRow->addWidget(convertButton);
    actionRow->addWidget(copyButton);
    actionRow->addStretch();
    actionRow->addWidget(clearButton);
    workLayout->addLayout(actionRow);
    workLayout->addWidget(createSectionLabel("Source Text"));
    workLayout->addWidget(sourceEdit_);
    workLayout->addWidget(createSectionLabel("Converted Result"));
    workLayout->addWidget(resultEdit_);
    workLayout->addWidget(copyOnlyLabel_);
    layout->addWidget(createPanel("converterPanel", "WORKFLOW", "Manual Conversion", "转换栏只处理用户明确提供的数据，不读取当前焦点字段。", workLayout));
    layout->addStretch();

    scroll->setWidget(canvas);

    setStyleSheet(R"(
        QFrame#converterHero { background: qlineargradient(x1:0, y1:0, x2:1, y2:1, stop:0 #1b4332, stop:0.55 #2d6a4f, stop:1 #95d5b2); border-radius: 24px; }
        QFrame#converterPanel { background: #fffdfa; border: 1px solid #d8d2c7; border-radius: 20px; }
        QLabel[role="hero-kicker"] { color: rgba(255,255,255,0.72); font-size: 12px; font-weight: 700; letter-spacing: 1px; }
        QLabel[role="hero-title"] { color: white; font-size: 28px; font-weight: 800; }
        QLabel[role="hero-body"], QLabel[role="hero-meta"] { color: rgba(255,255,255,0.84); font-size: 13px; }
        QLabel#converterStatusChip { background: rgba(255,255,255,0.16); color: white; border: 1px solid rgba(255,255,255,0.28); border-radius: 999px; padding: 7px 12px; font-weight: 700; }
        QLabel[role="eyebrow"] { color: #4d7a63; font-size: 11px; font-weight: 800; letter-spacing: 1px; }
        QLabel[role="panel-title"] { color: #20170f; font-size: 22px; font-weight: 800; }
        QLabel[role="panel-description"] { color: #746553; font-size: 13px; }
        QLabel[role="field-label"] { color: #3a2d22; font-size: 12px; font-weight: 700; }
        QTextEdit, QComboBox { background: #fffefd; border: 1px solid #d8cbb9; border-radius: 16px; padding: 12px 14px; color: #241a12; }
        QComboBox { min-height: 36px; }
        QPushButton { border-radius: 12px; padding: 10px 14px; font-weight: 700; border: none; }
        QPushButton[variant="primary"] { background: #2d6a4f; color: white; }
        QPushButton[variant="primary"]:hover { background: #23543f; }
        QPushButton[variant="secondary"] { background: #deefe6; color: #1b4d39; }
        QPushButton[variant="secondary"]:hover { background: #cfe7db; }
        QPushButton[variant="ghost"] { background: #f4efe7; color: #54483c; }
        QPushButton[variant="ghost"]:hover { background: #ece4d8; }
    )");

    connect(convertButton, &QPushButton::clicked, this, &ConverterSidePanel::handleConvert);
    connect(copyButton, &QPushButton::clicked, this, &ConverterSidePanel::handleCopy);
    connect(clearButton, &QPushButton::clicked, this, &ConverterSidePanel::handleClear);
}

void ConverterSidePanel::loadSource(const QString &text, const QString &sourceFormat, const QString &label)
{
    sourceEdit_->setText(text);
    const int index = sourceFormatCombo_->findText(sourceFormat);
    if (index >= 0) {
        sourceFormatCombo_->setCurrentIndex(index);
    }
    sourceLabel_->setText(QString("Source: %1").arg(label));
    setStatus("Loaded source into converter.", true);
}

void ConverterSidePanel::setStatus(const QString &message, bool success)
{
    applyStatusChip(statusChip_, message, success);
    emit statusMessageRequested(message, success);
}

void ConverterSidePanel::handleConvert()
{
    const auto result = ConverterService::convert(sourceEdit_->toPlainText(),
                                                  sourceFormatCombo_->currentText(),
                                                  targetFormatCombo_->currentText());
    if (!result.success) {
        resultEdit_->clear();
        setStatus(result.message, false);
        return;
    }

    resultEdit_->setText(result.text);
    setStatus("Conversion completed.", true);
}

void ConverterSidePanel::handleCopy()
{
    if (resultEdit_->toPlainText().isEmpty()) {
        setStatus("No converted result to copy.", false);
        return;
    }

    QApplication::clipboard()->setText(resultEdit_->toPlainText());
    setStatus("Converted result copied.", true);
}

void ConverterSidePanel::handleClear()
{
    sourceEdit_->clear();
    resultEdit_->clear();
    sourceLabel_->setText("Source: Manual input");
    setStatus("Converter workspace cleared.", true);
}
