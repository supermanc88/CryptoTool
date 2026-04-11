#ifndef WIDGETS_SM4PAGE_H
#define WIDGETS_SM4PAGE_H

#include <QWidget>

class QLabel;
class QComboBox;
class QLayout;
class QTextEdit;

class Sm4Page : public QWidget
{
    Q_OBJECT

public:
    explicit Sm4Page(QWidget *parent = nullptr);

signals:
    void statusMessageRequested(const QString &message, bool success);
    void sendToConverterRequested(const QString &text, const QString &sourceFormat, const QString &label);

private:
    QTextEdit *keyEdit_;
    QTextEdit *ivEdit_;
    QTextEdit *aadEdit_;
    QComboBox *modeCombo_;
    QComboBox *paddingCombo_;
    QTextEdit *inputEdit_;
    QTextEdit *outputEdit_;
    QTextEdit *tagEdit_;
    QLabel *statusChip_;

    void buildUi();
    QTextEdit *createEditor(const QString &placeholder, bool readOnly = false, int minimumHeight = 96) const;
    QWidget *createPanel(const QString &eyebrow,
                         const QString &title,
                         const QString &description,
                         QLayout *contentLayout) const;
    void setStatus(const QString &message, bool success);

private slots:
    void handleEncrypt();
    void handleDecrypt();
    void handleClear();
    void handleSendOutputToConverter();
    void handleSendTagToConverter();
};

#endif
