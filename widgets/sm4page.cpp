#include "widgets/sm4page.h"

#include "crypto/sm4_service.h"

#include <QComboBox>
#include <QFont>
#include <QFontDatabase>
#include <QFrame>
#include <QGridLayout>
#include <QHBoxLayout>
#include <QLabel>
#include <QPushButton>
#include <QScrollArea>
#include <QTextEdit>
#include <QVBoxLayout>

namespace {

QPushButton *createActionButton(const QString &text, const char *variant = "primary")
{
    auto *button = new QPushButton(text);
    button->setProperty("variant", variant);
    return button;
}

QWidget *createSectionLabel(const QString &text)
{
    auto *label = new QLabel(text);
    label->setProperty("role", "field-label");
    return label;
}

} // namespace

Sm4Page::Sm4Page(QWidget *parent)
    : QWidget(parent)
    , keyEdit_(nullptr)
    , ivEdit_(nullptr)
    , aadEdit_(nullptr)
    , modeCombo_(nullptr)
    , paddingCombo_(nullptr)
    , inputEdit_(nullptr)
    , outputEdit_(nullptr)
    , tagEdit_(nullptr)
    , statusChip_(nullptr)
{
    buildUi();
}

QTextEdit *Sm4Page::createEditor(const QString &placeholder, bool readOnly, int minimumHeight) const
{
    auto *edit = new QTextEdit;
    edit->setAcceptRichText(false);
    edit->setPlaceholderText(placeholder);
    edit->setReadOnly(readOnly);
    edit->setMinimumHeight(minimumHeight);

    QFont mono = QFontDatabase::systemFont(QFontDatabase::FixedFont);
    mono.setPointSizeF(12.0);
    edit->setFont(mono);
    return edit;
}

QWidget *Sm4Page::createPanel(const QString &eyebrow,
                              const QString &title,
                              const QString &description,
                              QLayout *contentLayout) const
{
    auto *panel = new QFrame;
    panel->setObjectName("sm4Panel");

    auto *layout = new QVBoxLayout(panel);
    layout->setContentsMargins(22, 22, 22, 22);
    layout->setSpacing(14);

    auto *eyebrowLabel = new QLabel(eyebrow, panel);
    eyebrowLabel->setProperty("role", "eyebrow");
    auto *titleLabel = new QLabel(title, panel);
    titleLabel->setProperty("role", "panel-title");
    auto *descriptionLabel = new QLabel(description, panel);
    descriptionLabel->setProperty("role", "panel-description");
    descriptionLabel->setWordWrap(true);

    contentLayout->setContentsMargins(0, 0, 0, 0);
    contentLayout->setSpacing(12);

    layout->addWidget(eyebrowLabel);
    layout->addWidget(titleLabel);
    layout->addWidget(descriptionLabel);
    layout->addSpacing(4);
    layout->addLayout(contentLayout);
    return panel;
}

void Sm4Page::buildUi()
{
    auto *scroll = new QScrollArea(this);
    scroll->setWidgetResizable(true);
    scroll->setFrameShape(QFrame::NoFrame);

    auto *canvas = new QWidget(scroll);
    auto *root = new QVBoxLayout(canvas);
    root->setContentsMargins(28, 28, 28, 28);
    root->setSpacing(22);

    auto *hero = new QFrame(canvas);
    hero->setObjectName("sm4Hero");
    auto *heroLayout = new QVBoxLayout(hero);
    heroLayout->setContentsMargins(28, 28, 28, 28);
    heroLayout->setSpacing(10);

    auto *heroKicker = new QLabel("SM4 Workspace", hero);
    heroKicker->setProperty("role", "hero-kicker");
    auto *heroTitle = new QLabel("对称加解密页面真正独立出来", hero);
    heroTitle->setProperty("role", "hero-title");
    auto *heroBody = new QLabel("把模式、IV、AAD、补位、输入输出拆成单独的信息层级，让 SM4 不再像旧 tab 一样堆在一个表单平面上。", hero);
    heroBody->setProperty("role", "hero-body");
    heroBody->setWordWrap(true);

    statusChip_ = new QLabel("Ready", hero);
    statusChip_->setObjectName("sm4StatusChip");

    auto *heroTop = new QHBoxLayout;
    heroTop->addWidget(heroKicker);
    heroTop->addStretch();
    heroTop->addWidget(statusChip_);

    heroLayout->addLayout(heroTop);
    heroLayout->addWidget(heroTitle);
    heroLayout->addWidget(heroBody);
    root->addWidget(hero);

    keyEdit_ = createEditor("Key hex", false, 120);
    ivEdit_ = createEditor("IV / nonce hex", false, 110);
    aadEdit_ = createEditor("AAD hex for AEAD modes", false, 110);
    modeCombo_ = new QComboBox;
    modeCombo_->addItems({"ECB", "CBC", "CFB", "OFB", "CTR", "GCM", "CCM", "XTS"});
    paddingCombo_ = new QComboBox;
    paddingCombo_->addItems({"是", "否"});
    inputEdit_ = createEditor("Input hex", false, 220);
    outputEdit_ = createEditor("Output hex", true, 220);
    tagEdit_ = createEditor("Authentication tag", true, 110);

    auto *grid = new QGridLayout;
    grid->setHorizontalSpacing(18);
    grid->setVerticalSpacing(18);

    auto *configLayout = new QVBoxLayout;
    configLayout->addWidget(createSectionLabel("Key"));
    configLayout->addWidget(keyEdit_);
    configLayout->addWidget(createSectionLabel("IV / Nonce"));
    configLayout->addWidget(ivEdit_);
    configLayout->addWidget(createSectionLabel("AAD"));
    configLayout->addWidget(aadEdit_);
    configLayout->addWidget(createSectionLabel("Mode"));
    configLayout->addWidget(modeCombo_);
    configLayout->addWidget(createSectionLabel("Padding"));
    configLayout->addWidget(paddingCombo_);
    grid->addWidget(createPanel("CONFIG", "Cipher Setup", "所有模式相关参数集中在左侧，避免输入、输出和配置互相打断。", configLayout), 0, 0, 2, 1);

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
    workLayout->addWidget(outputEdit_);
    grid->addWidget(createPanel("PROCESS", "Encrypt / Decrypt", "这里是主要工作区，专门承载输入数据和输出结果。", workLayout), 0, 1);

    auto *tagLayout = new QVBoxLayout;
    tagLayout->addWidget(createSectionLabel("Authentication Tag"));
    tagLayout->addWidget(tagEdit_);
    grid->addWidget(createPanel("AEAD", "Tag Surface", "GCM / CCM 生成的认证标签单独展示，不和主输出混在一起。", tagLayout), 1, 1);

    grid->setColumnStretch(0, 4);
    grid->setColumnStretch(1, 5);
    root->addLayout(grid);
    root->addStretch();

    scroll->setWidget(canvas);
    auto *pageLayout = new QVBoxLayout(this);
    pageLayout->setContentsMargins(0, 0, 0, 0);
    pageLayout->addWidget(scroll);

    setStyleSheet(R"(
        QFrame#sm4Hero {
            background: qlineargradient(x1:0, y1:0, x2:1, y2:1, stop:0 #16324f, stop:0.55 #8a5a44, stop:1 #d8a35d);
            border-radius: 28px;
        }
        QFrame#sm4Panel {
            background: #fffdfa;
            border: 1px solid #d8d2c7;
            border-radius: 22px;
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
        QLabel#sm4StatusChip {
            background: rgba(255,255,255,0.16);
            color: white;
            border: 1px solid rgba(255,255,255,0.28);
            border-radius: 999px;
            padding: 7px 12px;
            font-weight: 700;
        }
        QLabel[role="eyebrow"] {
            color: #8b6840;
            font-size: 11px;
            font-weight: 800;
            letter-spacing: 1px;
        }
        QLabel[role="panel-title"] {
            color: #20170f;
            font-size: 24px;
            font-weight: 800;
        }
        QLabel[role="panel-description"] {
            color: #746553;
            font-size: 13px;
        }
        QLabel[role="field-label"] {
            color: #3a2d22;
            font-size: 12px;
            font-weight: 700;
        }
        QTextEdit, QComboBox {
            background: #fffefd;
            border: 1px solid #d8cbb9;
            border-radius: 16px;
            padding: 12px 14px;
            color: #241a12;
        }
        QComboBox {
            min-height: 36px;
        }
        QPushButton {
            border-radius: 12px;
            padding: 11px 16px;
            font-weight: 700;
            border: none;
        }
        QPushButton[variant="primary"] {
            background: #8a5a44;
            color: white;
        }
        QPushButton[variant="primary"]:hover {
            background: #714936;
        }
        QPushButton[variant="secondary"] {
            background: #eee3dc;
            color: #6a4333;
        }
        QPushButton[variant="secondary"]:hover {
            background: #e4d5cb;
        }
        QPushButton[variant="ghost"] {
            background: #f4efe7;
            color: #54483c;
        }
        QPushButton[variant="ghost"]:hover {
            background: #ece4d8;
        }
    )");

    connect(encryptButton, &QPushButton::clicked, this, &Sm4Page::handleEncrypt);
    connect(decryptButton, &QPushButton::clicked, this, &Sm4Page::handleDecrypt);
    connect(clearButton, &QPushButton::clicked, this, &Sm4Page::handleClear);
}

void Sm4Page::setStatus(const QString &message, bool success)
{
    statusChip_->setText(message);
    statusChip_->setStyleSheet(success
        ? "background: rgba(255,255,255,0.18); color: white; border: 1px solid rgba(255,255,255,0.3); border-radius: 999px; padding: 7px 12px; font-weight: 700;"
        : "background: rgba(120,20,20,0.28); color: white; border: 1px solid rgba(255,255,255,0.26); border-radius: 999px; padding: 7px 12px; font-weight: 700;");
    emit statusMessageRequested(message, success);
}

void Sm4Page::handleEncrypt()
{
    const auto result = Crypto::Sm4Service::process(keyEdit_->toPlainText(),
                                                    inputEdit_->toPlainText(),
                                                    ivEdit_->toPlainText(),
                                                    aadEdit_->toPlainText(),
                                                    modeCombo_->currentText(),
                                                    paddingCombo_->currentText(),
                                                    true);
    if (!result.success) {
        setStatus(result.message, false);
        return;
    }

    outputEdit_->setText(result.primaryText);
    tagEdit_->setText(result.secondaryText);
    setStatus("SM4 encryption completed.", true);
}

void Sm4Page::handleDecrypt()
{
    const auto result = Crypto::Sm4Service::process(keyEdit_->toPlainText(),
                                                    inputEdit_->toPlainText(),
                                                    ivEdit_->toPlainText(),
                                                    aadEdit_->toPlainText(),
                                                    modeCombo_->currentText(),
                                                    paddingCombo_->currentText(),
                                                    false);
    if (!result.success) {
        setStatus(result.message, false);
        return;
    }

    outputEdit_->setText(result.primaryText);
    tagEdit_->setText(result.secondaryText);
    setStatus("SM4 decryption completed.", true);
}

void Sm4Page::handleClear()
{
    keyEdit_->clear();
    ivEdit_->clear();
    aadEdit_->clear();
    inputEdit_->clear();
    outputEdit_->clear();
    tagEdit_->clear();
    modeCombo_->setCurrentIndex(0);
    paddingCombo_->setCurrentIndex(0);
    setStatus("SM4 workspace cleared.", true);
}
