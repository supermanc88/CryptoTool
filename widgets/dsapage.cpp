#include "widgets/dsapage.h"

#include "crypto/dsa_service.h"
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

DsaPage::DsaPage(QWidget *parent)
    : QWidget(parent)
    , publicKeyEdit_(nullptr)
    , privateKeyEdit_(nullptr)
    , pEdit_(nullptr)
    , qEdit_(nullptr)
    , gEdit_(nullptr)
    , digestCombo_(nullptr)
    , dataEdit_(nullptr)
    , signatureEdit_(nullptr)
    , verifyResultEdit_(nullptr)
    , statusChip_(nullptr)
{
    buildUi();
}

void DsaPage::buildUi()
{
    auto *scroll = new QScrollArea(this);
    scroll->setWidgetResizable(true);
    scroll->setFrameShape(QFrame::NoFrame);

    auto *canvas = new QWidget(scroll);
    auto *root = new QVBoxLayout(canvas);
    root->setContentsMargins(28, 28, 28, 28);
    root->setSpacing(22);

    auto *hero = new QFrame(canvas);
    hero->setObjectName("dsaHero");
    auto *heroLayout = new QVBoxLayout(hero);
    heroLayout->setContentsMargins(28, 28, 28, 28);
    heroLayout->setSpacing(10);

    auto *heroTop = new QHBoxLayout;
    auto *heroKicker = new QLabel("DSA Workspace", hero);
    heroKicker->setProperty("role", "hero-kicker");
    statusChip_ = new QLabel("Ready", hero);
    statusChip_->setObjectName("dsaStatusChip");
    heroTop->addWidget(heroKicker);
    heroTop->addStretch();
    heroTop->addWidget(statusChip_);

    auto *heroTitle = new QLabel("参数、签名、验签分开读写", hero);
    heroTitle->setProperty("role", "hero-title");
    auto *heroBody = new QLabel("DSA 页面保留完整参数面，但把 keygen、sign、verify 的阅读路径拉直了。", hero);
    heroBody->setProperty("role", "hero-body");
    heroBody->setWordWrap(true);

    heroLayout->addLayout(heroTop);
    heroLayout->addWidget(heroTitle);
    heroLayout->addWidget(heroBody);
    root->addWidget(hero);

    publicKeyEdit_ = createEditor("Public key", false, 96);
    privateKeyEdit_ = createEditor("Private key", false, 96);
    pEdit_ = createEditor("Parameter p", false, 96);
    qEdit_ = createEditor("Parameter q", false, 96);
    gEdit_ = createEditor("Parameter g", false, 96);
    digestCombo_ = new QComboBox;
    digestCombo_->addItems({"sha1", "sha256", "sha224", "sha384", "sha512"});
    dataEdit_ = createEditor("Input data hex", false, 150);
    signatureEdit_ = createEditor("Signature output / input", false, 120);
    verifyResultEdit_ = createEditor("Verification result", true, 96);

    auto *grid = new QGridLayout;
    grid->setHorizontalSpacing(18);
    grid->setVerticalSpacing(18);

    auto *paramsLayout = new QVBoxLayout;
    auto *paramsActions = new QHBoxLayout;
    auto *generateButton = createActionButton("Generate Key Pair");
    auto *clearButton = createActionButton("Clear Workspace", "ghost");
    paramsActions->addWidget(generateButton);
    paramsActions->addStretch();
    paramsActions->addWidget(clearButton);
    paramsLayout->addLayout(paramsActions);
    paramsLayout->addWidget(createSectionLabel("Public Key"));
    paramsLayout->addWidget(publicKeyEdit_);
    paramsLayout->addWidget(createSectionLabel("Private Key"));
    paramsLayout->addWidget(privateKeyEdit_);
    paramsLayout->addWidget(createSectionLabel("Parameter p"));
    paramsLayout->addWidget(pEdit_);
    paramsLayout->addWidget(createSectionLabel("Parameter q"));
    paramsLayout->addWidget(qEdit_);
    paramsLayout->addWidget(createSectionLabel("Parameter g"));
    paramsLayout->addWidget(gEdit_);
    grid->addWidget(createPanel("dsaPanel", "FOUNDATION", "Key Material & Params", "把 DSA 的长参数区集中放在左侧，避免签名工作区被挤碎。", paramsLayout), 0, 0, 2, 1);

    auto *signLayout = new QVBoxLayout;
    auto *signButtons = new QHBoxLayout;
    auto *signButton = createActionButton("Sign");
    auto *verifyButton = createActionButton("Verify", "secondary");
    signButtons->addWidget(signButton);
    signButtons->addWidget(verifyButton);
    signButtons->addStretch();
    signLayout->addLayout(signButtons);
    signLayout->addWidget(createSectionLabel("Digest"));
    signLayout->addWidget(digestCombo_);
    signLayout->addWidget(createSectionLabel("Data"));
    signLayout->addWidget(dataEdit_);
    signLayout->addWidget(createSectionLabel("Signature"));
    signLayout->addWidget(signatureEdit_);
    signLayout->addWidget(createSectionLabel("Verify Result"));
    signLayout->addWidget(verifyResultEdit_);
    grid->addWidget(createPanel("dsaPanel", "OPERATIONS", "Sign & Verify", "签名和验签共享同一块上下文，减少参数重复确认。", signLayout), 0, 1, 2, 1);

    grid->setColumnStretch(0, 5);
    grid->setColumnStretch(1, 5);
    root->addLayout(grid);
    root->addStretch();

    scroll->setWidget(canvas);
    auto *pageLayout = new QVBoxLayout(this);
    pageLayout->setContentsMargins(0, 0, 0, 0);
    pageLayout->addWidget(scroll);

    setStyleSheet(R"(
        QFrame#dsaHero { background: qlineargradient(x1:0, y1:0, x2:1, y2:1, stop:0 #4b1d3f, stop:0.55 #7b3f61, stop:1 #c97b84); border-radius: 28px; }
        QFrame#dsaPanel { background: #fffdfa; border: 1px solid #d8d2c7; border-radius: 22px; }
        QLabel[role="hero-kicker"] { color: rgba(255,255,255,0.72); font-size: 12px; font-weight: 700; letter-spacing: 1px; }
        QLabel[role="hero-title"] { color: white; font-size: 32px; font-weight: 800; }
        QLabel[role="hero-body"] { color: rgba(255,255,255,0.84); font-size: 14px; }
        QLabel#dsaStatusChip { background: rgba(255,255,255,0.16); color: white; border: 1px solid rgba(255,255,255,0.28); border-radius: 999px; padding: 7px 12px; font-weight: 700; }
        QLabel[role="eyebrow"] { color: #8e5572; font-size: 11px; font-weight: 800; letter-spacing: 1px; }
        QLabel[role="panel-title"] { color: #20170f; font-size: 24px; font-weight: 800; }
        QLabel[role="panel-description"] { color: #746553; font-size: 13px; }
        QLabel[role="field-label"] { color: #3a2d22; font-size: 12px; font-weight: 700; }
        QTextEdit, QComboBox { background: #fffefd; border: 1px solid #d8cbb9; border-radius: 16px; padding: 12px 14px; color: #241a12; }
        QComboBox { min-height: 36px; }
        QPushButton { border-radius: 12px; padding: 11px 16px; font-weight: 700; border: none; }
        QPushButton[variant="primary"] { background: #7b3f61; color: white; }
        QPushButton[variant="primary"]:hover { background: #65344f; }
        QPushButton[variant="secondary"] { background: #f0dce5; color: #632f4d; }
        QPushButton[variant="secondary"]:hover { background: #e8cfdc; }
        QPushButton[variant="ghost"] { background: #f4efe7; color: #54483c; }
        QPushButton[variant="ghost"]:hover { background: #ece4d8; }
    )");

    connect(generateButton, &QPushButton::clicked, this, &DsaPage::handleGenerateKeyPair);
    connect(signButton, &QPushButton::clicked, this, &DsaPage::handleSign);
    connect(verifyButton, &QPushButton::clicked, this, &DsaPage::handleVerify);
    connect(clearButton, &QPushButton::clicked, this, &DsaPage::handleClear);
}

void DsaPage::setStatus(const QString &message, bool success)
{
    applyStatusChip(statusChip_, message, success);
    emit statusMessageRequested(message, success);
}

void DsaPage::handleGenerateKeyPair()
{
    const auto result = Crypto::DsaService::generateKeyPair();
    if (!result.success) {
        setStatus(result.message, false);
        return;
    }

    publicKeyEdit_->setText(result.publicKey);
    privateKeyEdit_->setText(result.privateKey);
    pEdit_->setText(result.p);
    qEdit_->setText(result.q);
    gEdit_->setText(result.g);
    setStatus("DSA key pair generated.", true);
}

void DsaPage::handleSign()
{
    const auto result = Crypto::DsaService::sign(publicKeyEdit_->toPlainText(),
                                                 privateKeyEdit_->toPlainText(),
                                                 dataEdit_->toPlainText(),
                                                 pEdit_->toPlainText(),
                                                 qEdit_->toPlainText(),
                                                 gEdit_->toPlainText(),
                                                 digestCombo_->currentText());
    if (!result.success) {
        setStatus(result.message, false);
        return;
    }

    signatureEdit_->setText(result.primaryText);
    setStatus("DSA signature generated.", true);
}

void DsaPage::handleVerify()
{
    const auto result = Crypto::DsaService::verify(publicKeyEdit_->toPlainText(),
                                                   dataEdit_->toPlainText(),
                                                   signatureEdit_->toPlainText(),
                                                   pEdit_->toPlainText(),
                                                   qEdit_->toPlainText(),
                                                   gEdit_->toPlainText(),
                                                   digestCombo_->currentText());
    if (!result.success) {
        verifyResultEdit_->setText(result.primaryText);
        setStatus(result.message, false);
        return;
    }

    verifyResultEdit_->setText(result.primaryText);
    setStatus("DSA verification completed.", true);
}

void DsaPage::handleClear()
{
    publicKeyEdit_->clear();
    privateKeyEdit_->clear();
    pEdit_->clear();
    qEdit_->clear();
    gEdit_->clear();
    dataEdit_->clear();
    signatureEdit_->clear();
    verifyResultEdit_->clear();
    setStatus("DSA workspace cleared.", true);
}
