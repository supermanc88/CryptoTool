#ifndef MAINWINDOW_H
#define MAINWINDOW_H

#include <QMainWindow>

QT_BEGIN_NAMESPACE
namespace Ui {
class MainWindow;
}
QT_END_NAMESPACE

class QListWidget;
class QStackedWidget;
class QWidget;
class Sm2Page;
class Sm3Page;
class Sm4Page;
class RsaPage;
class DsaPage;
class DigestPage;
class MacPage;
class StreamPage;
class UtilityPage;

class MainWindow : public QMainWindow
{
    Q_OBJECT

public:
    MainWindow(QWidget *parent = nullptr);
    ~MainWindow();

private:
    Ui::MainWindow *ui;
    QListWidget *navigationList_;
    QStackedWidget *pageStack_;
    Sm2Page *sm2Page_;
    Sm3Page *sm3Page_;
    Sm4Page *sm4Page_;
    RsaPage *rsaPage_;
    DsaPage *dsaPage_;
    DigestPage *digestPage_;
    MacPage *macPage_;
    StreamPage *streamPage_;
    UtilityPage *utilityPage_;

    void setupWindowShell();
    void applyWindowStyle();
    void showStatus(const QString &message, bool success = true) const;
};

#endif // MAINWINDOW_H
