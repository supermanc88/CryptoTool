#ifndef WIDGETS_CONVERTERSIDEPANEL_H
#define WIDGETS_CONVERTERSIDEPANEL_H

#include <QWidget>

class QLabel;
class QComboBox;
class QTextEdit;

class ConverterSidePanel : public QWidget
{
    Q_OBJECT

public:
    explicit ConverterSidePanel(QWidget *parent = nullptr);

    void loadSource(const QString &text, const QString &sourceFormat, const QString &label);

signals:
    void statusMessageRequested(const QString &message, bool success);

private:
    QLabel *statusChip_;
    QLabel *sourceLabel_;
    QLabel *copyOnlyLabel_;
    QComboBox *sourceFormatCombo_;
    QComboBox *targetFormatCombo_;
    QTextEdit *sourceEdit_;
    QTextEdit *resultEdit_;

    void buildUi();
    void setStatus(const QString &message, bool success);

private slots:
    void handleConvert();
    void handleCopy();
    void handleClear();
};

#endif // WIDGETS_CONVERTERSIDEPANEL_H
