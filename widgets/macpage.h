#ifndef WIDGETS_MACPAGE_H
#define WIDGETS_MACPAGE_H

#include <QWidget>

class QLabel;
class QComboBox;
class QTextEdit;

class MacPage : public QWidget
{
    Q_OBJECT

public:
    explicit MacPage(QWidget *parent = nullptr);

signals:
    void statusMessageRequested(const QString &message, bool success);

private:
    QComboBox *macModeCombo_;
    QComboBox *internalModeCombo_;
    QTextEdit *keyEdit_;
    QTextEdit *plainEdit_;
    QTextEdit *resultEdit_;
    QLabel *statusChip_;

    void buildUi();
    void setStatus(const QString &message, bool success);
    void refreshInternalModes();

private slots:
    void handleCalculate();
    void handleModeChanged(int index);
    void handleClear();
};

#endif // WIDGETS_MACPAGE_H
