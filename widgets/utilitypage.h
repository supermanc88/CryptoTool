#ifndef WIDGETS_UTILITYPAGE_H
#define WIDGETS_UTILITYPAGE_H

#include <QWidget>

class QLabel;
class QTextEdit;

class UtilityPage : public QWidget
{
    Q_OBJECT

public:
    explicit UtilityPage(QWidget *parent = nullptr);

signals:
    void statusMessageRequested(const QString &message, bool success);

private:
    QTextEdit *inputAEdit_;
    QTextEdit *inputBEdit_;
    QTextEdit *resultEdit_;
    QLabel *statusChip_;

    void buildUi();
    void setStatus(const QString &message, bool success);

private slots:
    void handleXor();
    void handleClear();
};

#endif // WIDGETS_UTILITYPAGE_H
