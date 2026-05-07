#include "widgets/aespage.h"

#include "crypto/aes_service.h"
#include "widgets/pagechrome.h"

#include <QComboBox>
#include <QFrame>
#include <QGridLayout>
#include <QHBoxLayout>
#include <QLabel>
#include <QPushButton>
#include <QVBoxLayout>

using namespace WidgetChrome;

AesPage::AesPage(QWidget *parent)
    : QWidget(parent)
    , modeCombo_(nullptr)
    , paddingCombo_(nullptr)
    , keyEdit_(nullptr)
    , ivEdit_(nullptr)
    , aadEdit_(nullptr)
    , inputEdit_(nullptr)
    , tagEdit_(nullptr)
    , outputEdit_(nullptr)
    , statusChip_(nullptr)
{
    buildUi();
}

void AesPage::buildUi()
{
    auto *root = new QVBoxLayout(this);
    root->setContentsMargins(0, 0, 0, 0);
    root->setSpacing(22);

    auto *header = new QFrame(this);
    header->setObjectName("aesHeader");
    auto *headerLayout = new QVBoxLayout(header);
    headerLayout->setContentsMargins(22, 22, 22, 22);
    headerLayout->setSpacing(10);

    auto *headerTop = new QHBoxLayout;
    auto *headerEyebrow = new QLabel("AES", header);
    headerEyebrow->setProperty("role", "eyebrow");
    statusChip_ = new QLabel("Ready", header);
    statusChip_->setObjectName("aesStatusChip");
    headerTop->addWidget(headerEyebrow);
    headerTop->addStretch();
    headerTop->addWidget(statusChip_);

    auto *headerTitle = new QLabel("AES 算法布局", header);
    headerTitle->setProperty("role", "content-title");
    auto *headerBody = new QLabel("保持块加密工作流的结构，同时把 AES 的 key size、IV / nonce 和 GCM tag 约束留在同一主页面里。", header);
    headerBody->setProperty("role", "panel-description");
    headerBody->setWordWrap(true);

    headerLayout->addLayout(headerTop);
    headerLayout->addWidget(headerTitle);
    headerLayout->addWidget(headerBody);
    root->addWidget(header);

    modeCombo_ = new QComboBox;
    modeCombo_->addItems({"ECB", "CBC", "CTR", "GCM"});
    paddingCombo_ = new QComboBox;
    paddingCombo_->addItems({"是", "否"});
    keyEdit_ = createEditor("Key hex (16 / 24 / 32 bytes)", false, 120);
    ivEdit_ = createEditor("IV / nonce hex", false, 110);
    aadEdit_ = createEditor("AAD hex for GCM", false, 110);
    inputEdit_ = createEditor("Input hex", false, 220);
    tagEdit_ = createEditor("GCM tag hex (required for decrypt, generated for encrypt)", false, 110);
    outputEdit_ = createEditor("Output hex", true, 220);

    auto *grid = new QGridLayout;
    grid->setHorizontalSpacing(18);
    grid->setVerticalSpacing(18);

    auto *configLayout = new QVBoxLayout;
    configLayout->addWidget(createSectionLabel("Mode"));
    configLayout->addWidget(modeCombo_);
    configLayout->addWidget(createSectionLabel("Padding"));
    configLayout->addWidget(paddingCombo_);
    configLayout->addWidget(createSectionLabel("Key"));
    configLayout->addWidget(keyEdit_);
    configLayout->addWidget(createSectionLabel("IV / Nonce"));
    configLayout->addWidget(ivEdit_);
    configLayout->addWidget(createSectionLabel("AAD"));
    configLayout->addWidget(aadEdit_);
    grid->addWidget(createPanel("aesPanel", "CONFIG", "Cipher Setup", "第一版支持常见块模式和一条 AEAD 路径，避免把 AES 做成难以维护的巨型面板。", configLayout), 0, 0, 2, 1);

    auto *workLayout = new QVBoxLayout;
    auto *actionRow = new QHBoxLayout;
    auto *encryptButton = createActionButton("Encrypt");
    auto *decryptButton = createActionButton("Decrypt", "secondary");
    auto *sendOutputButton = createActionButton("Send Output", "secondary");
    auto *clearButton = createActionButton("Clear Workspace", "ghost");
    actionRow->addWidget(encryptButton);
    actionRow->addWidget(decryptButton);
    actionRow->addWidget(sendOutputButton);
    actionRow->addStretch();
    actionRow->addWidget(clearButton);
    workLayout->addLayout(actionRow);
    workLayout->addWidget(createSectionLabel("Input"));
    workLayout->addWidget(inputEdit_);
    workLayout->addWidget(createSectionLabel("Output"));
    workLayout->addWidget(outputEdit_);
    grid->addWidget(createPanel("aesPanel", "PROCESS", "Encrypt / Decrypt", "输入和输出保持稳定工作区，不因为算法切换而重新学习页面。", workLayout), 0, 1);

    auto *tagLayout = new QVBoxLayout;
    auto *tagActions = new QHBoxLayout;
    auto *sendTagButton = createActionButton("Send Tag", "secondary");
    tagActions->addWidget(sendTagButton);
    tagActions->addStretch();
    tagLayout->addLayout(tagActions);
    tagLayout->addWidget(createSectionLabel("Authentication Tag"));
    tagLayout->addWidget(tagEdit_);
    grid->addWidget(createPanel("aesPanel", "AEAD", "Tag Surface", "GCM 解密读取这里的 tag，GCM 加密会把生成的 tag 回写到这里。", tagLayout), 1, 1);

    grid->setColumnStretch(0, 4);
    grid->setColumnStretch(1, 5);
    root->addLayout(grid);
    setStyleSheet(R"(
        QFrame#aesPanel { background: #fffdfa; border: 1px solid #d8d2c7; border-radius: 22px; }
        QFrame#aesHeader { background: #edf1f4; border: 1px solid #cbd7df; border-radius: 22px; }
        QLabel[role="content-title"] { color: #1e2b34; font-size: 26px; font-weight: 800; }
        QLabel#aesStatusChip { background: #dbe5eb; color: #24485f; border: 1px solid #c2d1db; border-radius: 999px; padding: 7px 12px; font-weight: 700; }
        QLabel[role="eyebrow"] { color: #8b6840; font-size: 11px; font-weight: 800; letter-spacing: 1px; }
        QLabel[role="panel-title"] { color: #20170f; font-size: 24px; font-weight: 800; }
        QLabel[role="panel-description"] { color: #746553; font-size: 13px; }
        QLabel[role="field-label"] { color: #3a2d22; font-size: 12px; font-weight: 700; }
        QTextEdit, QComboBox { background: #fffefd; border: 1px solid #d8cbb9; border-radius: 16px; padding: 12px 14px; color: #241a12; }
        QComboBox { min-height: 36px; }
        QPushButton { border-radius: 12px; padding: 11px 16px; font-weight: 700; border: none; }
        QPushButton[variant="primary"] { background: #2f6382; color: white; }
        QPushButton[variant="primary"]:hover { background: #28536d; }
        QPushButton[variant="secondary"] { background: #dce9f2; color: #22445b; }
        QPushButton[variant="secondary"]:hover { background: #cfdfeb; }
        QPushButton[variant="ghost"] { background: #f4efe7; color: #54483c; }
        QPushButton[variant="ghost"]:hover { background: #ece4d8; }
    )");

    connect(encryptButton, &QPushButton::clicked, this, &AesPage::handleEncrypt);
    connect(decryptButton, &QPushButton::clicked, this, &AesPage::handleDecrypt);
    connect(sendOutputButton, &QPushButton::clicked, this, &AesPage::handleSendOutputToConverter);
    connect(sendTagButton, &QPushButton::clicked, this, &AesPage::handleSendTagToConverter);
    connect(clearButton, &QPushButton::clicked, this, &AesPage::handleClear);
}

void AesPage::setStatus(const QString &message, bool success)
{
    applyStatusChip(statusChip_, message, success);
    emit statusMessageRequested(message, success);
}

void AesPage::handleEncrypt()
{
    const auto result = Crypto::AesService::process(keyEdit_->toPlainText(),
                                                    inputEdit_->toPlainText(),
                                                    ivEdit_->toPlainText(),
                                                    aadEdit_->toPlainText(),
                                                    tagEdit_->toPlainText(),
                                                    modeCombo_->currentText(),
                                                    paddingCombo_->currentText(),
                                                    true);
    if (!result.success) {
        setStatus(result.message, false);
        return;
    }

    outputEdit_->setText(result.primaryText);
    if (!result.secondaryText.isEmpty()) {
        tagEdit_->setText(result.secondaryText);
    }
    setStatus("AES encryption completed.", true);
}

void AesPage::handleDecrypt()
{
    const auto result = Crypto::AesService::process(keyEdit_->toPlainText(),
                                                    inputEdit_->toPlainText(),
                                                    ivEdit_->toPlainText(),
                                                    aadEdit_->toPlainText(),
                                                    tagEdit_->toPlainText(),
                                                    modeCombo_->currentText(),
                                                    paddingCombo_->currentText(),
                                                    false);
    if (!result.success) {
        setStatus(result.message, false);
        return;
    }

    outputEdit_->setText(result.primaryText);
    setStatus("AES decryption completed.", true);
}

void AesPage::handleClear()
{
    keyEdit_->clear();
    ivEdit_->clear();
    aadEdit_->clear();
    inputEdit_->clear();
    tagEdit_->clear();
    outputEdit_->clear();
    modeCombo_->setCurrentIndex(0);
    paddingCombo_->setCurrentIndex(0);
    setStatus("AES workspace cleared.", true);
}

void AesPage::handleSendOutputToConverter()
{
    if (outputEdit_->toPlainText().isEmpty()) {
        setStatus("No AES output to send.", false);
        return;
    }

    emit sendToConverterRequested(outputEdit_->toPlainText(), "Hex", "AES output");
}

void AesPage::handleSendTagToConverter()
{
    if (tagEdit_->toPlainText().isEmpty()) {
        setStatus("No AES tag to send.", false);
        return;
    }

    emit sendToConverterRequested(tagEdit_->toPlainText(), "Hex", "AES authentication tag");
}
