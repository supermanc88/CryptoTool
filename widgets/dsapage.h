#ifndef WIDGETS_DSAPAGE_H
#define WIDGETS_DSAPAGE_H

#include <QWidget>

class QLabel;
class QComboBox;
class QTextEdit;

class DsaPage : public QWidget
{
    Q_OBJECT

public:
    explicit DsaPage(QWidget *parent = nullptr);

signals:
    void statusMessageRequested(const QString &message, bool success);

private:
    QTextEdit *publicKeyEdit_;
    QTextEdit *privateKeyEdit_;
    QTextEdit *pEdit_;
    QTextEdit *qEdit_;
    QTextEdit *gEdit_;
    QComboBox *digestCombo_;
    QTextEdit *dataEdit_;
    QTextEdit *signatureEdit_;
    QTextEdit *verifyResultEdit_;
    QLabel *statusChip_;

    void buildUi();
    void setStatus(const QString &message, bool success);

private slots:
    void handleGenerateKeyPair();
    void handleSign();
    void handleVerify();
    void handleClear();
};

#endif // WIDGETS_DSAPAGE_H
