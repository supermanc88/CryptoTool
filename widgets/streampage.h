#ifndef WIDGETS_STREAMPAGE_H
#define WIDGETS_STREAMPAGE_H

#include <QWidget>

class QLabel;
class QComboBox;
class QTextEdit;

class StreamPage : public QWidget
{
    Q_OBJECT

public:
    explicit StreamPage(QWidget *parent = nullptr);

signals:
    void statusMessageRequested(const QString &message, bool success);

private:
    QComboBox *modeCombo_;
    QTextEdit *keyEdit_;
    QTextEdit *ivEdit_;
    QTextEdit *inputEdit_;
    QTextEdit *resultEdit_;
    QLabel *statusChip_;

    void buildUi();
    void setStatus(const QString &message, bool success);

private slots:
    void handleEncrypt();
    void handleDecrypt();
    void handleClear();
};

#endif // WIDGETS_STREAMPAGE_H
