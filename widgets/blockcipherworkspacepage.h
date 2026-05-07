#ifndef WIDGETS_BLOCKCIPHERWORKSPACEPAGE_H
#define WIDGETS_BLOCKCIPHERWORKSPACEPAGE_H

#include <QWidget>

class QLabel;
class QPushButton;
class QStackedWidget;
class Sm4Page;
class AesPage;

class BlockCipherWorkspacePage : public QWidget
{
    Q_OBJECT

public:
    explicit BlockCipherWorkspacePage(QWidget *parent = nullptr);

signals:
    void statusMessageRequested(const QString &message, bool success);
    void sendToConverterRequested(const QString &text, const QString &sourceFormat, const QString &label);

private:
    QPushButton *sm4SwitchButton_;
    QPushButton *aesSwitchButton_;
    QStackedWidget *pageStack_;
    Sm4Page *sm4Page_;
    AesPage *aesPage_;

    void buildUi();
    void switchAlgorithm(int index);
};

#endif // WIDGETS_BLOCKCIPHERWORKSPACEPAGE_H
