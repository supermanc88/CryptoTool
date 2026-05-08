#ifndef WIDGETS_AESPAGE_H
#define WIDGETS_AESPAGE_H

#include <QWidget>

class QLabel;
class QComboBox;
class QPushButton;
class QStackedWidget;
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
    QPushButton *cipherSwitchButton_;
    QPushButton *keyWrapSwitchButton_;
    QStackedWidget *workflowStack_;
    QComboBox *modeCombo_;
    QComboBox *paddingCombo_;
    QTextEdit *keyEdit_;
    QTextEdit *ivEdit_;
    QTextEdit *aadEdit_;
    QTextEdit *inputEdit_;
    QTextEdit *tagEdit_;
    QTextEdit *outputEdit_;
    QComboBox *wrapVariantCombo_;
    QTextEdit *kekEdit_;
    QTextEdit *wrapInputEdit_;
    QTextEdit *wrapOutputEdit_;
    QLabel *statusChip_;

    void buildUi();
    void setStatus(const QString &message, bool success);
    void switchWorkflow(int index);

private slots:
    void handleEncrypt();
    void handleDecrypt();
    void handleClear();
    void handleWrap();
    void handleUnwrap();
    void handleClearWrap();
    void handleSendOutputToConverter();
    void handleSendWrapOutputToConverter();
    void handleSendTagToConverter();
};

#endif // WIDGETS_AESPAGE_H
