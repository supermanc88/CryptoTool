#include "widgets/sm3page.h"

#include "crypto/sm2_service.h"
#include "crypto/sm3_service.h"

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

Sm3Page::Sm3Page(QWidget *parent)
    : QWidget(parent)
    , publicKeyEdit_(nullptr)
    , userIdEdit_(nullptr)
    , userIdTypeCombo_(nullptr)
    , messageEdit_(nullptr)
    , messageTypeCombo_(nullptr)
    , hashResultEdit_(nullptr)
    , statusChip_(nullptr)
{
    buildUi();
}

QTextEdit *Sm3Page::createEditor(const QString &placeholder, bool readOnly, int minimumHeight) const
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

QWidget *Sm3Page::createPanel(const QString &eyebrow,
                              const QString &title,
                              const QString &description,
                              QLayout *contentLayout) const
{
    auto *panel = new QFrame;
    panel->setObjectName("sm3Panel");

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

void Sm3Page::buildUi()
{
    auto *scroll = new QScrollArea(this);
    scroll->setWidgetResizable(true);
    scroll->setFrameShape(QFrame::NoFrame);

    auto *canvas = new QWidget(scroll);
    auto *root = new QVBoxLayout(canvas);
    root->setContentsMargins(28, 28, 28, 28);
    root->setSpacing(22);

    auto *hero = new QFrame(canvas);
    hero->setObjectName("sm3Hero");
    auto *heroLayout = new QVBoxLayout(hero);
    heroLayout->setContentsMargins(28, 28, 28, 28);
    heroLayout->setSpacing(10);

    auto *heroKicker = new QLabel("SM3 Workspace", hero);
    heroKicker->setProperty("role", "hero-kicker");
    auto *heroTitle = new QLabel("哈希与 ZA 计算分成两条清晰路径", hero);
    heroTitle->setProperty("role", "hero-title");
    auto *heroBody = new QLabel("这个页面不再复用旧 SM3 tab 的堆叠输入区，而是把普通哈希和 ZA 场景拆成清楚的输入面板。", hero);
    heroBody->setProperty("role", "hero-body");
    heroBody->setWordWrap(true);

    statusChip_ = new QLabel("Ready", hero);
    statusChip_->setObjectName("sm3StatusChip");

    auto *heroTop = new QHBoxLayout;
    heroTop->addWidget(heroKicker);
    heroTop->addStretch();
    heroTop->addWidget(statusChip_);

    heroLayout->addLayout(heroTop);
    heroLayout->addWidget(heroTitle);
    heroLayout->addWidget(heroBody);
    root->addWidget(hero);

    publicKeyEdit_ = createEditor("Public key for ZA mode", false, 140);
    userIdEdit_ = createEditor("User ID", false, 100);
    userIdTypeCombo_ = new QComboBox;
    userIdTypeCombo_->addItems({"String", "Hex"});
    messageEdit_ = createEditor("Message input", false, 180);
    messageTypeCombo_ = new QComboBox;
    messageTypeCombo_->addItems({"Hex", "String"});
    hashResultEdit_ = createEditor("Hash result", true, 200);

    auto *grid = new QGridLayout;
    grid->setHorizontalSpacing(18);
    grid->setVerticalSpacing(18);

    auto *inputLayout = new QVBoxLayout;
    inputLayout->addWidget(createSectionLabel("Message"));
    inputLayout->addWidget(messageEdit_);
    inputLayout->addWidget(createSectionLabel("Message Input Type"));
    inputLayout->addWidget(messageTypeCombo_);
    auto *hashButtonRow = new QHBoxLayout;
    auto *hashButton = createActionButton("Calculate SM3");
    auto *clearButton = createActionButton("Clear Workspace", "ghost");
    hashButtonRow->addWidget(hashButton);
    hashButtonRow->addStretch();
    hashButtonRow->addWidget(clearButton);
    inputLayout->addLayout(hashButtonRow);
    grid->addWidget(createPanel("CORE", "Plain Hash", "适合直接对字符串或十六进制输入做 SM3 计算。", inputLayout), 0, 0);

    auto *zaLayout = new QVBoxLayout;
    zaLayout->addWidget(createSectionLabel("Public Key"));
    zaLayout->addWidget(publicKeyEdit_);
    zaLayout->addWidget(createSectionLabel("User ID"));
    zaLayout->addWidget(userIdEdit_);
    zaLayout->addWidget(createSectionLabel("User ID Input Type"));
    zaLayout->addWidget(userIdTypeCombo_);
    auto *zaButtonRow = new QHBoxLayout;
    auto *zaButton = createActionButton("Calculate ZA Hash", "secondary");
    zaButtonRow->addWidget(zaButton);
    zaButtonRow->addStretch();
    zaLayout->addLayout(zaButtonRow);
    grid->addWidget(createPanel("ZA MODE", "Public Key + User ID", "需要计算 ZA 相关消息哈希时，补充公钥和用户 ID。", zaLayout), 0, 1);

    auto *resultLayout = new QVBoxLayout;
    auto *resultActions = new QHBoxLayout;
    auto *sendButton = createActionButton("Send Result to Converter", "secondary");
    resultActions->addWidget(sendButton);
    resultActions->addStretch();
    resultLayout->addLayout(resultActions);
    resultLayout->addWidget(createSectionLabel("Hash Result"));
    resultLayout->addWidget(hashResultEdit_);
    grid->addWidget(createPanel("OUTPUT", "Result Surface", "始终把结果放在单独输出区，避免和输入框混杂。", resultLayout), 1, 0, 1, 2);

    grid->setColumnStretch(0, 5);
    grid->setColumnStretch(1, 4);
    root->addLayout(grid);
    root->addStretch();

    scroll->setWidget(canvas);
    auto *pageLayout = new QVBoxLayout(this);
    pageLayout->setContentsMargins(0, 0, 0, 0);
    pageLayout->addWidget(scroll);

    setStyleSheet(R"(
        QFrame#sm3Hero {
            background: qlineargradient(x1:0, y1:0, x2:1, y2:1, stop:0 #3f2f56, stop:0.55 #245a77, stop:1 #7fb069);
            border-radius: 28px;
        }
        QFrame#sm3Panel {
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
        QLabel#sm3StatusChip {
            background: rgba(255,255,255,0.16);
            color: white;
            border: 1px solid rgba(255,255,255,0.28);
            border-radius: 999px;
            padding: 7px 12px;
            font-weight: 700;
        }
        QLabel[role="eyebrow"] {
            color: #7f6840;
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
            background: #245a77;
            color: white;
        }
        QPushButton[variant="primary"]:hover {
            background: #1d4a62;
        }
        QPushButton[variant="secondary"] {
            background: #e7eef3;
            color: #21485f;
        }
        QPushButton[variant="secondary"]:hover {
            background: #d8e5ed;
        }
        QPushButton[variant="ghost"] {
            background: #f4efe7;
            color: #54483c;
        }
        QPushButton[variant="ghost"]:hover {
            background: #ece4d8;
        }
    )");

    connect(hashButton, &QPushButton::clicked, this, &Sm3Page::handleHash);
    connect(zaButton, &QPushButton::clicked, this, &Sm3Page::handleHashZa);
    connect(sendButton, &QPushButton::clicked, this, &Sm3Page::handleSendToConverter);
    connect(clearButton, &QPushButton::clicked, this, &Sm3Page::handleClear);
}

void Sm3Page::setStatus(const QString &message, bool success)
{
    statusChip_->setText(message);
    statusChip_->setStyleSheet(success
        ? "background: rgba(255,255,255,0.18); color: white; border: 1px solid rgba(255,255,255,0.3); border-radius: 999px; padding: 7px 12px; font-weight: 700;"
        : "background: rgba(120,20,20,0.28); color: white; border: 1px solid rgba(255,255,255,0.26); border-radius: 999px; padding: 7px 12px; font-weight: 700;");
    emit statusMessageRequested(message, success);
}

void Sm3Page::handleHash()
{
    const auto result = Crypto::Sm3Service::hash(messageEdit_->toPlainText(), messageTypeCombo_->currentText());
    if (!result.success) {
        setStatus(result.message, false);
        return;
    }

    hashResultEdit_->setText(result.primaryText);
    setStatus("SM3 hash calculated.", true);
}

void Sm3Page::handleHashZa()
{
    const auto result = Crypto::Sm2Service::hashWithZa(publicKeyEdit_->toPlainText(),
                                                       userIdEdit_->toPlainText(),
                                                       userIdTypeCombo_->currentText(),
                                                       messageEdit_->toPlainText(),
                                                       messageTypeCombo_->currentText());
    if (!result.success) {
        setStatus(result.message, false);
        return;
    }

    hashResultEdit_->setText(result.primaryText);
    setStatus("SM3 ZA hash calculated.", true);
}

void Sm3Page::handleClear()
{
    publicKeyEdit_->clear();
    userIdEdit_->clear();
    messageEdit_->clear();
    hashResultEdit_->clear();
    messageTypeCombo_->setCurrentIndex(0);
    userIdTypeCombo_->setCurrentIndex(0);
    setStatus("SM3 workspace cleared.", true);
}

void Sm3Page::handleSendToConverter()
{
    if (hashResultEdit_->toPlainText().isEmpty()) {
        setStatus("No SM3 result to send.", false);
        return;
    }

    emit sendToConverterRequested(hashResultEdit_->toPlainText(), "Hex", "SM3 result");
}
