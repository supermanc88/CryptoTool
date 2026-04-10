#include "widgets/rsapage.h"

#include "crypto/rsa_service.h"
#include "widgets/pagechrome.h"

#include <QComboBox>
#include <QFrame>
#include <QGridLayout>
#include <QHBoxLayout>
#include <QLabel>
#include <QPushButton>
#include <QScrollArea>
#include <QTextEdit>
#include <QVBoxLayout>

using namespace WidgetChrome;

RsaPage::RsaPage(QWidget *parent)
    : QWidget(parent)
    , keyBitsCombo_(nullptr)
    , publicKeyEdit_(nullptr)
    , privateKeyEdit_(nullptr)
    , encryptPlainEdit_(nullptr)
    , encryptResultEdit_(nullptr)
    , decryptInputEdit_(nullptr)
    , decryptResultEdit_(nullptr)
    , statusChip_(nullptr)
{
    buildUi();
}

void RsaPage::buildUi()
{
    auto *scroll = new QScrollArea(this);
    scroll->setWidgetResizable(true);
    scroll->setFrameShape(QFrame::NoFrame);

    auto *canvas = new QWidget(scroll);
    auto *root = new QVBoxLayout(canvas);
    root->setContentsMargins(28, 28, 28, 28);
    root->setSpacing(22);

    auto *hero = new QFrame(canvas);
    hero->setObjectName("rsaHero");
    auto *heroLayout = new QVBoxLayout(hero);
    heroLayout->setContentsMargins(28, 28, 28, 28);
    heroLayout->setSpacing(10);

    auto *heroTop = new QHBoxLayout;
    auto *heroKicker = new QLabel("RSA Workspace", hero);
    heroKicker->setProperty("role", "hero-kicker");
    statusChip_ = new QLabel("Ready", hero);
    statusChip_->setObjectName("rsaStatusChip");
    heroTop->addWidget(heroKicker);
    heroTop->addStretch();
    heroTop->addWidget(statusChip_);

    auto *heroTitle = new QLabel("公钥体系页面改成真正的双工位布局", hero);
    heroTitle->setProperty("role", "hero-title");
    auto *heroBody = new QLabel("左侧负责密钥材料和参数，右侧拆成公钥加密与私钥解密，避免旧页面那种平面堆叠。", hero);
    heroBody->setProperty("role", "hero-body");
    heroBody->setWordWrap(true);

    heroLayout->addLayout(heroTop);
    heroLayout->addWidget(heroTitle);
    heroLayout->addWidget(heroBody);
    root->addWidget(hero);

    keyBitsCombo_ = new QComboBox;
    keyBitsCombo_->addItems({"1024", "2048", "3072", "4096"});
    publicKeyEdit_ = createEditor("Public key hex blob", false, 150);
    privateKeyEdit_ = createEditor("Private key hex blob", false, 150);
    encryptPlainEdit_ = createEditor("Plaintext hex", false, 160);
    encryptResultEdit_ = createEditor("Ciphertext output", true, 160);
    decryptInputEdit_ = createEditor("Ciphertext hex", false, 160);
    decryptResultEdit_ = createEditor("Plaintext output", true, 160);

    auto *grid = new QGridLayout;
    grid->setHorizontalSpacing(18);
    grid->setVerticalSpacing(18);

    auto *keysLayout = new QVBoxLayout;
    auto *keyActions = new QHBoxLayout;
    auto *generateButton = createActionButton("Generate Key Pair");
    auto *clearButton = createActionButton("Clear Workspace", "ghost");
    keyActions->addWidget(generateButton);
    keyActions->addStretch();
    keyActions->addWidget(clearButton);
    keysLayout->addLayout(keyActions);
    keysLayout->addWidget(createSectionLabel("Key Size"));
    keysLayout->addWidget(keyBitsCombo_);
    keysLayout->addWidget(createSectionLabel("Public Key"));
    keysLayout->addWidget(publicKeyEdit_);
    keysLayout->addWidget(createSectionLabel("Private Key"));
    keysLayout->addWidget(privateKeyEdit_);
    grid->addWidget(createPanel("rsaPanel", "FOUNDATION", "Key Material", "先生成或粘贴密钥，再进入公钥加密或私钥解密。", keysLayout), 0, 0, 2, 1);

    auto *encryptLayout = new QVBoxLayout;
    auto *encryptRow = new QHBoxLayout;
    auto *encryptButton = createActionButton("Encrypt with Public Key");
    encryptRow->addWidget(encryptButton);
    encryptRow->addStretch();
    encryptLayout->addLayout(encryptRow);
    encryptLayout->addWidget(createSectionLabel("Plaintext"));
    encryptLayout->addWidget(encryptPlainEdit_);
    encryptLayout->addWidget(createSectionLabel("Ciphertext"));
    encryptLayout->addWidget(encryptResultEdit_);
    grid->addWidget(createPanel("rsaPanel", "PUBLIC OP", "Encrypt", "公钥操作单独占据一个区域，便于快速试算。", encryptLayout), 0, 1);

    auto *decryptLayout = new QVBoxLayout;
    auto *decryptRow = new QHBoxLayout;
    auto *decryptButton = createActionButton("Decrypt with Private Key", "secondary");
    decryptRow->addWidget(decryptButton);
    decryptRow->addStretch();
    decryptLayout->addLayout(decryptRow);
    decryptLayout->addWidget(createSectionLabel("Ciphertext"));
    decryptLayout->addWidget(decryptInputEdit_);
    decryptLayout->addWidget(createSectionLabel("Plaintext"));
    decryptLayout->addWidget(decryptResultEdit_);
    grid->addWidget(createPanel("rsaPanel", "PRIVATE OP", "Decrypt", "私钥解密结果与加密区分开，阅读路径更稳定。", decryptLayout), 1, 1);

    grid->setColumnStretch(0, 5);
    grid->setColumnStretch(1, 5);
    root->addLayout(grid);
    root->addStretch();

    scroll->setWidget(canvas);
    auto *pageLayout = new QVBoxLayout(this);
    pageLayout->setContentsMargins(0, 0, 0, 0);
    pageLayout->addWidget(scroll);

    setStyleSheet(R"(
        QFrame#rsaHero {
            background: qlineargradient(x1:0, y1:0, x2:1, y2:1, stop:0 #23395b, stop:0.55 #406e8e, stop:1 #8ea8c3);
            border-radius: 28px;
        }
        QFrame#rsaPanel {
            background: #fffdfa;
            border: 1px solid #d8d2c7;
            border-radius: 22px;
        }
        QLabel[role="hero-kicker"] { color: rgba(255,255,255,0.72); font-size: 12px; font-weight: 700; letter-spacing: 1px; }
        QLabel[role="hero-title"] { color: white; font-size: 32px; font-weight: 800; }
        QLabel[role="hero-body"] { color: rgba(255,255,255,0.84); font-size: 14px; }
        QLabel#rsaStatusChip { background: rgba(255,255,255,0.16); color: white; border: 1px solid rgba(255,255,255,0.28); border-radius: 999px; padding: 7px 12px; font-weight: 700; }
        QLabel[role="eyebrow"] { color: #6d6b95; font-size: 11px; font-weight: 800; letter-spacing: 1px; }
        QLabel[role="panel-title"] { color: #20170f; font-size: 24px; font-weight: 800; }
        QLabel[role="panel-description"] { color: #746553; font-size: 13px; }
        QLabel[role="field-label"] { color: #3a2d22; font-size: 12px; font-weight: 700; }
        QTextEdit, QComboBox { background: #fffefd; border: 1px solid #d8cbb9; border-radius: 16px; padding: 12px 14px; color: #241a12; }
        QComboBox { min-height: 36px; }
        QPushButton { border-radius: 12px; padding: 11px 16px; font-weight: 700; border: none; }
        QPushButton[variant="primary"] { background: #406e8e; color: white; }
        QPushButton[variant="primary"]:hover { background: #355d79; }
        QPushButton[variant="secondary"] { background: #e3ebf2; color: #25465d; }
        QPushButton[variant="secondary"]:hover { background: #d7e2eb; }
        QPushButton[variant="ghost"] { background: #f4efe7; color: #54483c; }
        QPushButton[variant="ghost"]:hover { background: #ece4d8; }
    )");

    connect(generateButton, &QPushButton::clicked, this, &RsaPage::handleGenerateKeyPair);
    connect(encryptButton, &QPushButton::clicked, this, &RsaPage::handleEncrypt);
    connect(decryptButton, &QPushButton::clicked, this, &RsaPage::handleDecrypt);
    connect(clearButton, &QPushButton::clicked, this, &RsaPage::handleClear);
}

void RsaPage::setStatus(const QString &message, bool success)
{
    applyStatusChip(statusChip_, message, success);
    emit statusMessageRequested(message, success);
}

void RsaPage::handleGenerateKeyPair()
{
    const auto result = Crypto::RsaService::generateKeyPair(keyBitsCombo_->currentText().toInt());
    if (!result.success) {
        setStatus(result.message, false);
        return;
    }

    publicKeyEdit_->setText(result.publicKey);
    privateKeyEdit_->setText(result.privateKey);
    setStatus("RSA key pair generated.", true);
}

void RsaPage::handleEncrypt()
{
    const auto result = Crypto::RsaService::encrypt(publicKeyEdit_->toPlainText(),
                                                    privateKeyEdit_->toPlainText(),
                                                    encryptPlainEdit_->toPlainText());
    if (!result.success) {
        setStatus(result.message, false);
        return;
    }

    encryptResultEdit_->setText(result.primaryText);
    setStatus("RSA encryption completed.", true);
}

void RsaPage::handleDecrypt()
{
    const auto result = Crypto::RsaService::decrypt(privateKeyEdit_->toPlainText(),
                                                    decryptInputEdit_->toPlainText());
    if (!result.success) {
        setStatus(result.message, false);
        return;
    }

    decryptResultEdit_->setText(result.primaryText);
    setStatus("RSA decryption completed.", true);
}

void RsaPage::handleClear()
{
    publicKeyEdit_->clear();
    privateKeyEdit_->clear();
    encryptPlainEdit_->clear();
    encryptResultEdit_->clear();
    decryptInputEdit_->clear();
    decryptResultEdit_->clear();
    setStatus("RSA workspace cleared.", true);
}
