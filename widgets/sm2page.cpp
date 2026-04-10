#include "widgets/sm2page.h"

#include "crypto/sm2_service.h"

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

Sm2Page::Sm2Page(QWidget *parent)
    : QWidget(parent)
    , publicKeyEdit_(nullptr)
    , privateKeyEdit_(nullptr)
    , signDigestEdit_(nullptr)
    , signatureEdit_(nullptr)
    , verifyResultEdit_(nullptr)
    , encryptPlainEdit_(nullptr)
    , encryptCipherEdit_(nullptr)
    , decryptCipherEdit_(nullptr)
    , decryptPlainEdit_(nullptr)
    , statusChip_(nullptr)
{
    buildUi();
}

QTextEdit *Sm2Page::createEditor(const QString &placeholder, bool readOnly, int minimumHeight) const
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

QWidget *Sm2Page::createPanel(const QString &eyebrow,
                              const QString &title,
                              const QString &description,
                              QLayout *contentLayout) const
{
    auto *panel = new QFrame;
    panel->setObjectName("sm2Panel");

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

void Sm2Page::buildUi()
{
    auto *scroll = new QScrollArea(this);
    scroll->setWidgetResizable(true);
    scroll->setFrameShape(QFrame::NoFrame);

    auto *canvas = new QWidget(scroll);
    auto *root = new QVBoxLayout(canvas);
    root->setContentsMargins(28, 28, 28, 28);
    root->setSpacing(22);

    auto *hero = new QFrame(canvas);
    hero->setObjectName("sm2Hero");
    auto *heroLayout = new QVBoxLayout(hero);
    heroLayout->setContentsMargins(28, 28, 28, 28);
    heroLayout->setSpacing(10);

    auto *heroKicker = new QLabel("SM2 Workspace", hero);
    heroKicker->setProperty("role", "hero-kicker");
    auto *heroTitle = new QLabel("重新设计的国密工作台", hero);
    heroTitle->setProperty("role", "hero-title");
    auto *heroBody = new QLabel("把密钥、签名、验签、加密、解密拆成清晰的工作区，不再沿用旧 `.ui` 页面上的密集控件堆叠。", hero);
    heroBody->setProperty("role", "hero-body");
    heroBody->setWordWrap(true);

    statusChip_ = new QLabel("Ready", hero);
    statusChip_->setObjectName("sm2StatusChip");

    auto *heroTop = new QHBoxLayout;
    heroTop->addWidget(heroKicker);
    heroTop->addStretch();
    heroTop->addWidget(statusChip_);

    heroLayout->addLayout(heroTop);
    heroLayout->addWidget(heroTitle);
    heroLayout->addWidget(heroBody);

    root->addWidget(hero);

    auto *grid = new QGridLayout;
    grid->setHorizontalSpacing(18);
    grid->setVerticalSpacing(18);

    publicKeyEdit_ = createEditor("04... uncompressed public key", false, 150);
    privateKeyEdit_ = createEditor("Private key hex", false, 150);
    signDigestEdit_ = createEditor("Digest / hash hex", false, 120);
    signatureEdit_ = createEditor("Signature result", false, 120);
    verifyResultEdit_ = createEditor("Verification result", true, 96);
    encryptPlainEdit_ = createEditor("Plaintext hex", false, 150);
    encryptCipherEdit_ = createEditor("Ciphertext result", true, 150);
    decryptCipherEdit_ = createEditor("Ciphertext hex", false, 150);
    decryptPlainEdit_ = createEditor("Plaintext result", true, 150);

    auto *keyActions = new QHBoxLayout;
    auto *generateKeysButton = createActionButton("Generate Key Pair");
    auto *derivePubButton = createActionButton("Derive Public Key", "secondary");
    auto *clearButton = createActionButton("Clear Workspace", "ghost");
    keyActions->addWidget(generateKeysButton);
    keyActions->addWidget(derivePubButton);
    keyActions->addStretch();
    keyActions->addWidget(clearButton);

    auto *keysLayout = new QVBoxLayout;
    keysLayout->addLayout(keyActions);
    keysLayout->addWidget(createSectionLabel("Public Key"));
    keysLayout->addWidget(publicKeyEdit_);
    keysLayout->addWidget(createSectionLabel("Private Key"));
    keysLayout->addWidget(privateKeyEdit_);
    grid->addWidget(createPanel("FOUNDATION", "Key Material", "先把密钥准备好，后面的签名、加密、解密都会共用这里的输入。", keysLayout), 0, 0, 2, 1);

    auto *signLayout = new QVBoxLayout;
    auto *signButtons = new QHBoxLayout;
    auto *signButton = createActionButton("Sign Digest");
    auto *verifyButton = createActionButton("Verify Signature", "secondary");
    signButtons->addWidget(signButton);
    signButtons->addWidget(verifyButton);
    signButtons->addStretch();
    signLayout->addLayout(signButtons);
    signLayout->addWidget(createSectionLabel("Digest / Message Hash"));
    signLayout->addWidget(signDigestEdit_);
    signLayout->addWidget(createSectionLabel("Signature"));
    signLayout->addWidget(signatureEdit_);
    signLayout->addWidget(createSectionLabel("Verify Result"));
    signLayout->addWidget(verifyResultEdit_);
    grid->addWidget(createPanel("SIGNATURE", "Sign & Verify", "把签名流和验签反馈放在同一个卡片里，避免旧页面那种上下跳跃。", signLayout), 0, 1);

    auto *encryptLayout = new QVBoxLayout;
    auto *encryptButtonRow = new QHBoxLayout;
    auto *encryptButton = createActionButton("Encrypt with Public Key");
    encryptButtonRow->addWidget(encryptButton);
    encryptButtonRow->addStretch();
    encryptLayout->addLayout(encryptButtonRow);
    encryptLayout->addWidget(createSectionLabel("Plaintext"));
    encryptLayout->addWidget(encryptPlainEdit_);
    encryptLayout->addWidget(createSectionLabel("Ciphertext"));
    encryptLayout->addWidget(encryptCipherEdit_);
    grid->addWidget(createPanel("ENCRYPTION", "Public Key Encryption", "给需要快速测试公钥加密的人一个独立操作区。", encryptLayout), 1, 1);

    auto *decryptLayout = new QVBoxLayout;
    auto *decryptButtonRow = new QHBoxLayout;
    auto *decryptButton = createActionButton("Decrypt with Private Key");
    decryptButtonRow->addWidget(decryptButton);
    decryptButtonRow->addStretch();
    decryptLayout->addLayout(decryptButtonRow);
    decryptLayout->addWidget(createSectionLabel("Ciphertext"));
    decryptLayout->addWidget(decryptCipherEdit_);
    decryptLayout->addWidget(createSectionLabel("Plaintext"));
    decryptLayout->addWidget(decryptPlainEdit_);
    grid->addWidget(createPanel("DECRYPTION", "Private Key Decryption", "把解密结果单独展示，避免和签名区、公钥区混在一起。", decryptLayout), 2, 0, 1, 2);

    grid->setColumnStretch(0, 6);
    grid->setColumnStretch(1, 5);
    root->addLayout(grid);
    root->addStretch();

    scroll->setWidget(canvas);

    auto *pageLayout = new QVBoxLayout(this);
    pageLayout->setContentsMargins(0, 0, 0, 0);
    pageLayout->addWidget(scroll);

    setStyleSheet(R"(
        QFrame#sm2Hero {
            background: qlineargradient(x1:0, y1:0, x2:1, y2:1, stop:0 #173f5f, stop:0.55 #1f6f5f, stop:1 #dba24a);
            border-radius: 28px;
        }
        QFrame#sm2Panel {
            background: #fffdfa;
            border: 1px solid #dccfbf;
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
            font-size: 34px;
            font-weight: 800;
        }
        QLabel[role="hero-body"] {
            color: rgba(255,255,255,0.84);
            font-size: 14px;
            line-height: 1.5;
        }
        QLabel#sm2StatusChip {
            background: rgba(255,255,255,0.16);
            color: white;
            border: 1px solid rgba(255,255,255,0.28);
            border-radius: 999px;
            padding: 7px 12px;
            font-weight: 700;
        }
        QLabel[role="eyebrow"] {
            color: #8d6f44;
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
        QTextEdit {
            background: #fffefd;
            border: 1px solid #d8cbb9;
            border-radius: 16px;
            padding: 12px 14px;
            color: #241a12;
        }
        QPushButton {
            border-radius: 12px;
            padding: 11px 16px;
            font-weight: 700;
            border: none;
        }
        QPushButton[variant="primary"] {
            background: #1f6f5f;
            color: white;
        }
        QPushButton[variant="primary"]:hover {
            background: #18594d;
        }
        QPushButton[variant="secondary"] {
            background: #e7f0ed;
            color: #17483e;
        }
        QPushButton[variant="secondary"]:hover {
            background: #d6e8e2;
        }
        QPushButton[variant="ghost"] {
            background: #f4efe7;
            color: #54483c;
        }
        QPushButton[variant="ghost"]:hover {
            background: #ece4d8;
        }
    )");

    connect(generateKeysButton, &QPushButton::clicked, this, &Sm2Page::handleGenerateKeyPair);
    connect(derivePubButton, &QPushButton::clicked, this, &Sm2Page::handleDerivePublicKey);
    connect(signButton, &QPushButton::clicked, this, &Sm2Page::handleSign);
    connect(verifyButton, &QPushButton::clicked, this, &Sm2Page::handleVerify);
    connect(encryptButton, &QPushButton::clicked, this, &Sm2Page::handleEncrypt);
    connect(decryptButton, &QPushButton::clicked, this, &Sm2Page::handleDecrypt);
    connect(clearButton, &QPushButton::clicked, this, &Sm2Page::handleClear);
}

void Sm2Page::setStatus(const QString &message, bool success)
{
    statusChip_->setText(message);
    statusChip_->setStyleSheet(success
        ? "background: rgba(255,255,255,0.18); color: white; border: 1px solid rgba(255,255,255,0.3); border-radius: 999px; padding: 7px 12px; font-weight: 700;"
        : "background: rgba(120,20,20,0.28); color: white; border: 1px solid rgba(255,255,255,0.26); border-radius: 999px; padding: 7px 12px; font-weight: 700;");
    emit statusMessageRequested(message, success);
}

void Sm2Page::handleGenerateKeyPair()
{
    const auto result = Crypto::Sm2Service::generateKeyPair();
    if (!result.success) {
        setStatus(result.message, false);
        return;
    }

    publicKeyEdit_->setText(result.publicKey);
    privateKeyEdit_->setText(result.privateKey);
    setStatus("SM2 key pair generated.", true);
}

void Sm2Page::handleDerivePublicKey()
{
    const auto result = Crypto::Sm2Service::derivePublicKey(privateKeyEdit_->toPlainText());
    if (!result.success) {
        setStatus(result.message, false);
        return;
    }

    publicKeyEdit_->setText(result.primaryText);
    setStatus("Public key derived from private key.", true);
}

void Sm2Page::handleSign()
{
    const auto result = Crypto::Sm2Service::signHash(privateKeyEdit_->toPlainText(), signDigestEdit_->toPlainText());
    if (!result.success) {
        setStatus(result.message, false);
        return;
    }

    signatureEdit_->setText(result.primaryText);
    setStatus("SM2 signature generated.", true);
}

void Sm2Page::handleVerify()
{
    const auto result = Crypto::Sm2Service::verifySignature(publicKeyEdit_->toPlainText(),
                                                            signDigestEdit_->toPlainText(),
                                                            signatureEdit_->toPlainText());
    verifyResultEdit_->setText(result.success ? result.primaryText : result.message);
    setStatus(result.success ? "Signature verified." : result.message, result.success);
}

void Sm2Page::handleEncrypt()
{
    const auto result = Crypto::Sm2Service::encrypt(publicKeyEdit_->toPlainText(), encryptPlainEdit_->toPlainText());
    if (!result.success) {
        setStatus(result.message, false);
        return;
    }

    encryptCipherEdit_->setText(result.primaryText);
    setStatus("SM2 encryption completed.", true);
}

void Sm2Page::handleDecrypt()
{
    const auto result = Crypto::Sm2Service::decrypt(privateKeyEdit_->toPlainText(), decryptCipherEdit_->toPlainText());
    if (!result.success) {
        setStatus(result.message, false);
        return;
    }

    decryptPlainEdit_->setText(result.primaryText);
    setStatus("SM2 decryption completed.", true);
}

void Sm2Page::handleClear()
{
    publicKeyEdit_->clear();
    privateKeyEdit_->clear();
    signDigestEdit_->clear();
    signatureEdit_->clear();
    verifyResultEdit_->clear();
    encryptPlainEdit_->clear();
    encryptCipherEdit_->clear();
    decryptCipherEdit_->clear();
    decryptPlainEdit_->clear();
    setStatus("SM2 workspace cleared.", true);
}
