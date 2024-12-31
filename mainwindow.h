#ifndef MAINWINDOW_H
#define MAINWINDOW_H

#include <QMainWindow>

QT_BEGIN_NAMESPACE
namespace Ui {
class MainWindow;
}
QT_END_NAMESPACE

class MainWindow : public QMainWindow
{
    Q_OBJECT

public:
    MainWindow(QWidget *parent = nullptr);
    ~MainWindow();

private slots:

    void on_pushButton_gen_sm2_keypair_clicked();

    void on_pushButton_sm2_prikey_sign_clicked();

    void on_pushButton_sm2_pubkey_verify_clicked();

    void on_pushButton_sm2_pubkey_encrypt_clicked();

    void on_pushButton_sm2_prikey_decrypt_clicked();

    void on_pushButton_sm3_hash_clicked();

    void on_pushButton_sm3_hash_ZA_clicked();

    void on_pushButton_sm2_tab_clear_clicked();

    void on_pushButton_sm3_tab_clear_clicked();

    void on_pushButton_sm4_encrypt_clicked();

    void on_pushButton_gen_rsa_keypair_clicked();

    void on_pushButton_rsa_prikey_operation_clicked();

    void on_pushButton_rsa_pubkey_operation_clicked();

    void on_pushButton_gen_dsa_keypair_clicked();

    void on_pushButton_dsa_sign_operation_clicked();

private:
    Ui::MainWindow *ui;
    void generate_sm2_keypair();
    void sm2_prikey_sign_hash();

};
#endif // MAINWINDOW_H
