#include "mainwindow.h"
#include "./ui_mainwindow.h"

#include <openssl/ec.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/bio.h>
#include <openssl/err.h>
#include <QDebug>
#include <QRegularExpression>

MainWindow::MainWindow(QWidget *parent)
    : QMainWindow(parent)
    , ui(new Ui::MainWindow)
{

    ui->setupUi(this);

}

MainWindow::~MainWindow()
{
    delete ui;
}



// 将 BIGNUM 转为十六进制字符串
QString BNToHex(const BIGNUM *bn) {
    char *hex = BN_bn2hex(bn);
    QString hexStr(hex);
    OPENSSL_free(hex);
    return hexStr;
}

void MainWindow::generate_sm2_keypair()
{
    EVP_PKEY_CTX *p_ctx = NULL;
    EVP_PKEY *pkey = NULL;
    EC_KEY *ec_key = NULL;
    BIGNUM *priv_key = NULL;
    EC_POINT *pub_key = NULL;
    QString priv_key_str;;
    QString pub_key_str;;
    char *pubKeyHex = NULL;

    // 创建密钥对上下文
    p_ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_EC, NULL);
    if (!p_ctx) {
        qDebug() << "Failed to create EVP_PKEY_CTX.";
        goto out;
    }

    // 初始化密钥对上下文
    if (EVP_PKEY_keygen_init(p_ctx) <= 0) {
        qDebug() << "Failed to initialize key generation.";
        goto out;
    }

    // 设置密钥对参数
    if (EVP_PKEY_CTX_set_ec_paramgen_curve_nid(p_ctx, NID_sm2) <= 0) {
        qDebug() << "Failed to set curve NID.";
        goto out;
    }

    // 生成密钥对
    if (EVP_PKEY_keygen(p_ctx, &pkey) <= 0) {
        qDebug() << "Failed to generate key pair.";
        goto out;
    }

    // 获取 EC_KEY 对象
    ec_key = (EC_KEY *)EVP_PKEY_get0_EC_KEY(pkey);

    // 获取私钥
    priv_key = (BIGNUM *)EC_KEY_get0_private_key(ec_key);
    if (!priv_key) {
        qDebug() << "Failed to get private key.";
        goto out;
    }

    // 获取公钥
    pub_key = (EC_POINT *)EC_KEY_get0_public_key(ec_key);
    if (!pub_key) {
        qDebug() << "Failed to get public key.";
        goto out;
    }

    // 将私钥转换为十六进制字符串
    priv_key_str = BNToHex(priv_key);
    qDebug() << "Private Key:" << priv_key_str;

    // 将公钥转换为十六进制字符串
    pub_key_str = EC_POINT_point2hex(EC_KEY_get0_group(ec_key), pub_key, POINT_CONVERSION_UNCOMPRESSED, NULL);
    qDebug() << "Public Key:" << pub_key_str;

    ui->textEdit_sm2_prikey->setText(priv_key_str);
    ui->textEdit_sm2_pubkey->setText(pub_key_str);


out:
    if (p_ctx) {
        EVP_PKEY_CTX_free(p_ctx);
    }
    if (pkey) {
        EVP_PKEY_free(pkey);
    }
}


// sm2 private key sign hash
void MainWindow::sm2_prikey_sign_hash()
{
    // 获取 textEdit_sm2_prikey 中的私钥字符串
    QString priv_key_str = ui->textEdit_sm2_prikey->toPlainText();
    qDebug() << "priv_key_str:" << priv_key_str;

    QByteArray priv_key_bytes = QByteArray::fromHex(priv_key_str.toUtf8());

    // 获取 textEdit_sm2_sign_data 中的 hash 字符串
    QString hash_str = ui->textEdit_sm2_sign_data->toPlainText();
    qDebug() << "hash_str:" << hash_str;

    QByteArray hash_bytes = QByteArray::fromHex(hash_str.toUtf8());

    BIGNUM *priv_key = NULL;
    EC_KEY *ec_key = NULL;
    EVP_PKEY *pkey = NULL;
    EVP_PKEY_CTX *pkctx = NULL;

    QString sig_str = NULL;
    size_t sig_len = 0;
    unsigned char *sig = NULL;


    ec_key = EC_KEY_new_by_curve_name(NID_sm2);
    if (!ec_key) {
        qDebug() << "Failed to create EC_KEY.";
        goto out;
    }

    // 设置私钥到 EC_KEY
    priv_key = BN_bin2bn((const unsigned char *)priv_key_bytes.constData(), priv_key_bytes.size(), NULL);
    if (!priv_key ) {
        qDebug() << "Failed to convert private key.";
        goto out;
    }

    if (EC_KEY_set_private_key(ec_key, priv_key) != 1) {
        qDebug() << "Failed to set private key to EC_KEY.";
        goto out;
    }

    // 创建 EVP_PKEY 对象
    pkey = EVP_PKEY_new();
    if (!pkey) {
        qDebug() << "Failed to create EVP_PKEY.";
        goto out;
    }

    if (EVP_PKEY_set1_EC_KEY(pkey, ec_key) != 1) {
        qDebug() << "Failed to assign EC_KEY to EVP_PKEY.";
        goto out;
    }

    // 创建签名上下文
    pkctx = EVP_PKEY_CTX_new(pkey, NULL);
    if (!pkctx) {
        qDebug() << "Failed to create EVP_PKEY_CTX.";
        goto out;
    }

    // 初始化签名上下文
    if (EVP_PKEY_sign_init(pkctx) <= 0) {
        qDebug() << "Failed to initialize signing context.";
        goto out;
    }

    // 计算签名长度
    sig_len = 72;
    sig = (unsigned char *)OPENSSL_malloc(sig_len);
    if (!sig) {
        qDebug() << "Failed to allocate memory for signature.";
        goto out;
    }

    // 签名
    if (EVP_PKEY_sign(pkctx, sig, &sig_len, (const unsigned char *)hash_bytes.constData(), hash_bytes.size()) <= 0) {
        qDebug() << "Failed to sign hash.";
        goto out;
    }

    // 将签名转换为十六进制字符串
    sig_str = QByteArray(reinterpret_cast<char *>(sig), sig_len).toHex();
    qDebug() << "Signature:" << sig_str;

    ui->textEdit_sm2_sign_value->setText(sig_str);


out:
    if (priv_key) {
        BN_free(priv_key);
    }
    if (ec_key) {
        EC_KEY_free(ec_key);
    }
    if (pkey) {
        EVP_PKEY_free(pkey);
    }
    if (pkctx) {
        EVP_PKEY_CTX_free(pkctx);
    }
    if (sig) {
        OPENSSL_free(sig);
    }

}



void MainWindow::on_pushButton_gen_sm2_keypair_clicked()
{
    generate_sm2_keypair();
}





void MainWindow::on_pushButton_sm2_prikey_sign_clicked()
{
    sm2_prikey_sign_hash();
}


void MainWindow::on_pushButton_sm2_pubkey_verify_clicked()
{
    // 获取 UI 中的输入
    QString pubkeyStr = ui->textEdit_sm2_pubkey->toPlainText().remove(QRegularExpression("\\s")); // 清除空格或换行符
    QString hashStr = ui->textEdit_sm2_sign_data->toPlainText().remove(QRegularExpression("\\s")); // 清除空格或换行符
    QString sigStr = ui->textEdit_sm2_sign_value->toPlainText().remove(QRegularExpression("\\s")); // 清除空格或换行符

    qDebug() << "Public Key:" << pubkeyStr;
    qDebug() << "Hash:" << hashStr;
    qDebug() << "Signature:" << sigStr;

    // 将输入字符串转换为字节数组
    QByteArray hashBytes = QByteArray::fromHex(hashStr.toUtf8());
    QByteArray sigBytes = QByteArray::fromHex(sigStr.toUtf8());
    QByteArray pubkeyBytes = QByteArray::fromHex(pubkeyStr.toUtf8());

    EC_KEY *ec_key = NULL;
    EVP_PKEY *pkey = NULL;
    EVP_PKEY_CTX *pkctx = NULL;

    ec_key = EC_KEY_new_by_curve_name(NID_sm2);
    if (!ec_key) {
        qDebug() << "Failed to create EC_KEY.";
        goto out;
    }

    // 设置公钥到 EC_KEY
    if (EC_KEY_oct2key(ec_key, (const unsigned char *)pubkeyBytes.constData(), pubkeyBytes.size(), NULL) != 1) {
        qDebug() << "Failed to set public key to EC_KEY.";
        goto out;
    }

    // 创建 EVP_PKEY 对象
    pkey = EVP_PKEY_new();
    if (!pkey) {
        qDebug() << "Failed to create EVP_PKEY.";
        goto out;
    }

    if (EVP_PKEY_set1_EC_KEY(pkey, ec_key) != 1) {
        qDebug() << "Failed to assign EC_KEY to EVP_PKEY.";
        goto out;
    }

    // 创建签名上下文
    pkctx = EVP_PKEY_CTX_new(pkey, NULL);
    if (!pkctx) {
        qDebug() << "Failed to create EVP_PKEY_CTX.";
        goto out;
    }

    // 初始化签名上下文
    if (EVP_PKEY_verify_init(pkctx) <= 0) {
        qDebug() << "Failed to initialize verification context.";
        goto out;
    }

    // 验证签名
    if (EVP_PKEY_verify(pkctx, (const unsigned char *)sigBytes.constData(), sigBytes.size(), (const unsigned char *)hashBytes.constData(), hashBytes.size()) <= 0) {
        qDebug() << "Failed to verify signature.";
        ui->textEdit_sm2_verify_result->setText("Failed to verify signature.");
    } else {
        qDebug() << "Signature verified.";
        ui->textEdit_sm2_verify_result->setText("Signature verified.");
    }


out:
    if (ec_key) {
        EC_KEY_free(ec_key);
    }
    if (pkey) {
        EVP_PKEY_free(pkey);
    }
    if (pkctx) {
        EVP_PKEY_CTX_free(pkctx);
    }

}


void MainWindow::on_pushButton_sm2_pubkey_encrypt_clicked()
{
    // 获取 UI 中的输入
    QString pubkeyStr = ui->textEdit_sm2_pubkey->toPlainText().remove(QRegularExpression("\\s")); // 清除空格或换行符
    QString plaintextStr = ui->textEdit_sm2_encrypt_plain->toPlainText().remove(QRegularExpression("\\s")); // 清除空格或换行符

    qDebug() << "Public Key:" << pubkeyStr;
    qDebug() << "Plaintext:" << plaintextStr;

    QByteArray plaintextBytes = QByteArray::fromHex(plaintextStr.toUtf8());
    QByteArray pubkeyBytes = QByteArray::fromHex(pubkeyStr.toUtf8());


    EC_KEY *ec_key = NULL;
    EVP_PKEY *pkey = NULL;
    EVP_PKEY_CTX *pkctx = NULL;

    QString ciphertextStr = NULL;
    size_t ciphertext_len = 0;
    unsigned char *ciphertext = NULL;

    ec_key = EC_KEY_new_by_curve_name(NID_sm2);
    if (!ec_key) {
        qDebug() << "Failed to create EC_KEY.";
        goto out;
    }

    // set public key to EC_KEY
    if (EC_KEY_oct2key(ec_key, (const unsigned char *)pubkeyBytes.constData(), pubkeyBytes.size(), NULL) != 1) {
        qDebug() << "Failed to set public key to EC_KEY.";
        goto out;
    }

    // create EVP_PKEY object
    pkey = EVP_PKEY_new();
    if (!pkey) {
        qDebug() << "Failed to create EVP_PKEY.";
        goto out;
    }

    if (EVP_PKEY_set1_EC_KEY(pkey, ec_key) != 1) {
        qDebug() << "Failed to assign EC_KEY to EVP_PKEY.";
        goto out;
    }

    // create encryption context
    pkctx = EVP_PKEY_CTX_new(pkey, NULL);
    if (!pkctx) {
        qDebug() << "Failed to create EVP_PKEY_CTX.";
        goto out;
    }

    // initialize encryption context
    if (EVP_PKEY_encrypt_init(pkctx) <= 0) {
        qDebug() << "Failed to initialize encryption context.";
        goto out;
    }

    // calculate ciphertext length
    ciphertext_len = plaintextBytes.size() + 128;
    ciphertext = (unsigned char *)OPENSSL_malloc(ciphertext_len);
    if (!ciphertext) {
        qDebug() << "Failed to allocate memory for ciphertext.";
        goto out;
    }

    // encrypt
    if (EVP_PKEY_encrypt(pkctx, ciphertext, &ciphertext_len, (const unsigned char *)plaintextBytes.constData(), plaintextBytes.size()) <= 0) {
        qDebug() << "Failed to encrypt plaintext.";
        goto out;
    }

    // convert ciphertext to hex string
    ciphertextStr = QByteArray(reinterpret_cast<char *>(ciphertext), ciphertext_len).toHex();
    qDebug() << "Ciphertext:" << ciphertextStr;

    ui->textEdit_sm2_encrypt_result->setText(ciphertextStr);



out:
    if (ec_key) {
        EC_KEY_free(ec_key);
    }
    if (pkey) {
        EVP_PKEY_free(pkey);
    }
    if (pkctx) {
        EVP_PKEY_CTX_free(pkctx);
    }
    if (ciphertext) {
        OPENSSL_free(ciphertext);
    }

}


void MainWindow::on_pushButton_sm2_prikey_decrypt_clicked()
{

    // 获取 UI 中的输入
    QString privkeyStr = ui->textEdit_sm2_prikey->toPlainText().remove(QRegularExpression("\\s")); // 清除空格或换行符
    QString ciphertextStr = ui->textEdit_sm2_decrypt_plain->toPlainText().remove(QRegularExpression("\\s")); // 清除空格或换行符

    qDebug() << "Private Key:" << privkeyStr;
    qDebug() << "Ciphertext:" << ciphertextStr;

    QByteArray ciphertextBytes = QByteArray::fromHex(ciphertextStr.toUtf8());
    QByteArray privkeyBytes = QByteArray::fromHex(privkeyStr.toUtf8());

    QString plaintextStr = NULL;

    EC_KEY *ec_key = NULL;
    EVP_PKEY *pkey = NULL;
    EVP_PKEY_CTX *pkctx = NULL;
    BIGNUM *priv_key = NULL;
    size_t plaintext_len = 0;
    unsigned char *plaintext = NULL;

    ec_key = EC_KEY_new_by_curve_name(NID_sm2);
    if (!ec_key) {
        qDebug() << "Failed to create EC_KEY.";
        goto out;
    }

    // set private key to EC_KEY
    priv_key = BN_bin2bn((const unsigned char *)privkeyBytes.constData(), privkeyBytes.size(), NULL);
    if (!priv_key) {
        qDebug() << "Failed to convert private key.";
        goto out;
    }

    if (EC_KEY_set_private_key(ec_key, priv_key) != 1) {
        qDebug() << "Failed to set private key to EC_KEY.";
        goto out;
    }

    // create EVP_PKEY object
    pkey = EVP_PKEY_new();
    if (!pkey) {
        qDebug() << "Failed to create EVP_PKEY.";
        goto out;
    }

    if (EVP_PKEY_set1_EC_KEY(pkey, ec_key) != 1) {
        qDebug() << "Failed to assign EC_KEY to EVP_PKEY.";
        goto out;
    }

    // create decryption context
    pkctx = EVP_PKEY_CTX_new(pkey, NULL);
    if (!pkctx) {
        qDebug() << "Failed to create EVP_PKEY_CTX.";
        goto out;
    }

    // initialize decryption context
    if (EVP_PKEY_decrypt_init(pkctx) <= 0) {
        qDebug() << "Failed to initialize decryption context.";
        goto out;
    }

    // calculate plaintext length
    plaintext_len = ciphertextBytes.size();
    plaintext = (unsigned char *)OPENSSL_malloc(plaintext_len);

    if (!plaintext) {
        qDebug() << "Failed to allocate memory for plaintext.";
        goto out;
    }

    // decrypt
    if (EVP_PKEY_decrypt(pkctx, plaintext, &plaintext_len, (const unsigned char *)ciphertextBytes.constData(), ciphertextBytes.size()) <= 0) {
        qDebug() << "Failed to decrypt ciphertext.";
        goto out;
    }

    // convert plaintext to hex string
    plaintextStr = QByteArray(reinterpret_cast<char *>(plaintext), plaintext_len).toHex();
    qDebug() << "Plaintext:" << plaintextStr;

    ui->textEdit_sm2_decrypt_result->setText(plaintextStr);

out:
    if (ec_key) {
        EC_KEY_free(ec_key);
    }
    if (pkey) {
        EVP_PKEY_free(pkey);
    }
    if (pkctx) {
        EVP_PKEY_CTX_free(pkctx);
    }
    if (priv_key) {
        BN_free(priv_key);
    }
    if (plaintext) {
        OPENSSL_free(plaintext);
    }

}

