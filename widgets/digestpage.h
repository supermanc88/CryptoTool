#ifndef WIDGETS_DIGESTPAGE_H
#define WIDGETS_DIGESTPAGE_H

#include <QWidget>

class QLabel;
class QComboBox;
class QTextEdit;

class DigestPage : public QWidget
{
    Q_OBJECT

public:
    explicit DigestPage(QWidget *parent = nullptr);

signals:
    void statusMessageRequested(const QString &message, bool success);

private:
    QComboBox *digestCombo_;
    QTextEdit *plainEdit_;
    QTextEdit *resultEdit_;
    QLabel *statusChip_;

    void buildUi();
    void setStatus(const QString &message, bool success);

private slots:
    void handleCalculate();
    void handleClear();
};

#endif // WIDGETS_DIGESTPAGE_H
