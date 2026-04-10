#ifndef WIDGETS_RSAPAGE_H
#define WIDGETS_RSAPAGE_H

#include <QWidget>

class QLabel;
class QComboBox;
class QTextEdit;

class RsaPage : public QWidget
{
    Q_OBJECT

public:
    explicit RsaPage(QWidget *parent = nullptr);

signals:
    void statusMessageRequested(const QString &message, bool success);

private:
    QComboBox *keyBitsCombo_;
    QTextEdit *publicKeyEdit_;
    QTextEdit *privateKeyEdit_;
    QTextEdit *encryptPlainEdit_;
    QTextEdit *encryptResultEdit_;
    QTextEdit *decryptInputEdit_;
    QTextEdit *decryptResultEdit_;
    QLabel *statusChip_;

    void buildUi();
    void setStatus(const QString &message, bool success);

private slots:
    void handleGenerateKeyPair();
    void handleEncrypt();
    void handleDecrypt();
    void handleClear();
};

#endif // WIDGETS_RSAPAGE_H
