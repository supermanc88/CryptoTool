#ifndef WIDGETS_SM2PAGE_H
#define WIDGETS_SM2PAGE_H

#include <QWidget>

class QLabel;
class QLayout;
class QTextEdit;

class Sm2Page : public QWidget
{
    Q_OBJECT

public:
    explicit Sm2Page(QWidget *parent = nullptr);

signals:
    void statusMessageRequested(const QString &message, bool success);

private:
    QTextEdit *publicKeyEdit_;
    QTextEdit *privateKeyEdit_;
    QTextEdit *signDigestEdit_;
    QTextEdit *signatureEdit_;
    QTextEdit *verifyResultEdit_;
    QTextEdit *encryptPlainEdit_;
    QTextEdit *encryptCipherEdit_;
    QTextEdit *decryptCipherEdit_;
    QTextEdit *decryptPlainEdit_;
    QLabel *statusChip_;

    void buildUi();
    QTextEdit *createEditor(const QString &placeholder, bool readOnly = false, int minimumHeight = 96) const;
    QWidget *createPanel(const QString &eyebrow,
                         const QString &title,
                         const QString &description,
                         QLayout *contentLayout) const;
    void setStatus(const QString &message, bool success);

private slots:
    void handleGenerateKeyPair();
    void handleDerivePublicKey();
    void handleSign();
    void handleVerify();
    void handleEncrypt();
    void handleDecrypt();
    void handleClear();
};

#endif
