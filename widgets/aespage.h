#ifndef WIDGETS_AESPAGE_H
#define WIDGETS_AESPAGE_H

#include <QWidget>

class QLabel;
class QComboBox;
class QTextEdit;

class AesPage : public QWidget
{
    Q_OBJECT

public:
    explicit AesPage(QWidget *parent = nullptr);

signals:
    void statusMessageRequested(const QString &message, bool success);
    void sendToConverterRequested(const QString &text, const QString &sourceFormat, const QString &label);

private:
    QComboBox *modeCombo_;
    QComboBox *paddingCombo_;
    QTextEdit *keyEdit_;
    QTextEdit *ivEdit_;
    QTextEdit *aadEdit_;
    QTextEdit *inputEdit_;
    QTextEdit *tagEdit_;
    QTextEdit *outputEdit_;
    QLabel *statusChip_;

    void buildUi();
    void setStatus(const QString &message, bool success);

private slots:
    void handleEncrypt();
    void handleDecrypt();
    void handleClear();
    void handleSendOutputToConverter();
    void handleSendTagToConverter();
};

#endif // WIDGETS_AESPAGE_H
