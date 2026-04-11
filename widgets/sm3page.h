#ifndef WIDGETS_SM3PAGE_H
#define WIDGETS_SM3PAGE_H

#include <QWidget>

class QLabel;
class QComboBox;
class QLayout;
class QTextEdit;

class Sm3Page : public QWidget
{
    Q_OBJECT

public:
    explicit Sm3Page(QWidget *parent = nullptr);

signals:
    void statusMessageRequested(const QString &message, bool success);
    void sendToConverterRequested(const QString &text, const QString &sourceFormat, const QString &label);

private:
    QTextEdit *publicKeyEdit_;
    QTextEdit *userIdEdit_;
    QComboBox *userIdTypeCombo_;
    QTextEdit *messageEdit_;
    QComboBox *messageTypeCombo_;
    QTextEdit *hashResultEdit_;
    QLabel *statusChip_;

    void buildUi();
    QTextEdit *createEditor(const QString &placeholder, bool readOnly = false, int minimumHeight = 96) const;
    QWidget *createPanel(const QString &eyebrow,
                         const QString &title,
                         const QString &description,
                         QLayout *contentLayout) const;
    void setStatus(const QString &message, bool success);

private slots:
    void handleHash();
    void handleHashZa();
    void handleClear();
    void handleSendToConverter();
};

#endif
