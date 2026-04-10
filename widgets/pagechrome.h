#ifndef WIDGETS_PAGECHROME_H
#define WIDGETS_PAGECHROME_H

#include <QFont>
#include <QFontDatabase>
#include <QFrame>
#include <QLabel>
#include <QLayout>
#include <QPushButton>
#include <QTextEdit>
#include <QVBoxLayout>

namespace WidgetChrome {

inline QPushButton *createActionButton(const QString &text, const char *variant = "primary")
{
    auto *button = new QPushButton(text);
    button->setProperty("variant", variant);
    return button;
}

inline QLabel *createSectionLabel(const QString &text)
{
    auto *label = new QLabel(text);
    label->setProperty("role", "field-label");
    return label;
}

inline QTextEdit *createEditor(const QString &placeholder, bool readOnly = false, int minimumHeight = 96)
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

inline QWidget *createPanel(const QString &objectName,
                            const QString &eyebrow,
                            const QString &title,
                            const QString &description,
                            QLayout *contentLayout)
{
    auto *panel = new QFrame;
    panel->setObjectName(objectName);

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

inline void applyStatusChip(QLabel *label, const QString &message, bool success)
{
    if (!label) {
        return;
    }

    label->setText(message);
    label->setStyleSheet(success
        ? "background: rgba(255,255,255,0.18); color: white; border: 1px solid rgba(255,255,255,0.3); border-radius: 999px; padding: 7px 12px; font-weight: 700;"
        : "background: rgba(120,20,20,0.28); color: white; border: 1px solid rgba(255,255,255,0.26); border-radius: 999px; padding: 7px 12px; font-weight: 700;");
}

} // namespace WidgetChrome

#endif // WIDGETS_PAGECHROME_H
