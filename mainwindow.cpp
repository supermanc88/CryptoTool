#include "mainwindow.h"
#include "./ui_mainwindow.h"

#include <openssl/ec.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/rsa.h>

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


void MainWindow::on_pushButton_sm3_hash_clicked()
{
    QString hash_str = NULL;
    QString hash_result = NULL;


    hash_str = ui->textEdit_sm3_plain->toPlainText();
    qDebug() << "hash_str:" << hash_str;
    QByteArray hash_bytes = QByteArray::fromHex(hash_str.toUtf8());


    unsigned char hash[32];
    unsigned int hash_len = 32;

    EVP_MD_CTX *md_ctx = NULL;

    md_ctx = EVP_MD_CTX_new();
    if (!md_ctx) {
        qDebug() << "Failed to create EVP_MD_CTX.";
        goto out;
    }

    if (EVP_DigestInit(md_ctx, EVP_sm3()) != 1) {
        qDebug() << "Failed to initialize SM3 digest.";
        goto out;
    }

    if (EVP_DigestUpdate(md_ctx, (const unsigned char *)hash_bytes.constData(), hash_bytes.size()) != 1) {
        qDebug() << "Failed to update SM3 digest.";
        goto out;
    }

    if (EVP_DigestFinal(md_ctx, hash, &hash_len) != 1) {
        qDebug() << "Failed to finalize SM3 digest.";
        goto out;
    }

    hash_result = QByteArray(reinterpret_cast<char *>(hash), hash_len).toHex();
    qDebug() << "Hash:" << hash_result;

    ui->textEdit_sm3_hash_result->setText(hash_result);


out:
    if (md_ctx) {
        EVP_MD_CTX_free(md_ctx);
    }
}


int sm2_compute_z_digest(uint8_t *out,
                         const EVP_MD *digest,
                         const uint8_t *id,
                         const size_t id_len,
                         const EC_KEY *key)
{
    int rc = 0;
    const EC_GROUP *group = EC_KEY_get0_group(key);
    BN_CTX *ctx = NULL;
    EVP_MD_CTX *hash = NULL;
    BIGNUM *p = NULL;
    BIGNUM *a = NULL;
    BIGNUM *b = NULL;
    BIGNUM *xG = NULL;
    BIGNUM *yG = NULL;
    BIGNUM *xA = NULL;
    BIGNUM *yA = NULL;
    int p_bytes = 0;
    uint8_t *buf = NULL;
    uint16_t entl = 0;
    uint8_t e_byte = 0;

    hash = EVP_MD_CTX_new();
    ctx = BN_CTX_new();
    if (hash == NULL || ctx == NULL) {
        SM2err(SM2_F_SM2_COMPUTE_Z_DIGEST, ERR_R_MALLOC_FAILURE);
        goto done;
    }

    p = BN_CTX_get(ctx);
    a = BN_CTX_get(ctx);
    b = BN_CTX_get(ctx);
    xG = BN_CTX_get(ctx);
    yG = BN_CTX_get(ctx);
    xA = BN_CTX_get(ctx);
    yA = BN_CTX_get(ctx);

    if (yA == NULL) {
        SM2err(SM2_F_SM2_COMPUTE_Z_DIGEST, ERR_R_MALLOC_FAILURE);
        goto done;
    }

    if (!EVP_DigestInit(hash, digest)) {
        SM2err(SM2_F_SM2_COMPUTE_Z_DIGEST, ERR_R_EVP_LIB);
        goto done;
    }

    /* Z = h(ENTL || ID || a || b || xG || yG || xA || yA) */

    if (id_len >= (UINT16_MAX / 8)) {
        /* too large */
        // SM2err(SM2_F_SM2_COMPUTE_Z_DIGEST, SM2_R_ID_TOO_LARGE);
        qDebug() << "ID too large";
        goto done;
    }

    entl = (uint16_t)(8 * id_len);

    e_byte = entl >> 8;
    if (!EVP_DigestUpdate(hash, &e_byte, 1)) {
        SM2err(SM2_F_SM2_COMPUTE_Z_DIGEST, ERR_R_EVP_LIB);
        goto done;
    }
    e_byte = entl & 0xFF;
    if (!EVP_DigestUpdate(hash, &e_byte, 1)) {
        SM2err(SM2_F_SM2_COMPUTE_Z_DIGEST, ERR_R_EVP_LIB);
        goto done;
    }

    if (id_len > 0 && !EVP_DigestUpdate(hash, id, id_len)) {
        SM2err(SM2_F_SM2_COMPUTE_Z_DIGEST, ERR_R_EVP_LIB);
        goto done;
    }

    if (!EC_GROUP_get_curve(group, p, a, b, ctx)) {
        SM2err(SM2_F_SM2_COMPUTE_Z_DIGEST, ERR_R_EC_LIB);
        goto done;
    }

    p_bytes = BN_num_bytes(p);
    buf = (uint8_t *)OPENSSL_zalloc(p_bytes);
    if (buf == NULL) {
        SM2err(SM2_F_SM2_COMPUTE_Z_DIGEST, ERR_R_MALLOC_FAILURE);
        goto done;
    }

    if (BN_bn2binpad(a, buf, p_bytes) < 0
        || !EVP_DigestUpdate(hash, buf, p_bytes)
        || BN_bn2binpad(b, buf, p_bytes) < 0
        || !EVP_DigestUpdate(hash, buf, p_bytes)
        || !EC_POINT_get_affine_coordinates(group,
                                            EC_GROUP_get0_generator(group),
                                            xG, yG, ctx)
        || BN_bn2binpad(xG, buf, p_bytes) < 0
        || !EVP_DigestUpdate(hash, buf, p_bytes)
        || BN_bn2binpad(yG, buf, p_bytes) < 0
        || !EVP_DigestUpdate(hash, buf, p_bytes)
        || !EC_POINT_get_affine_coordinates(group,
                                            EC_KEY_get0_public_key(key),
                                            xA, yA, ctx)
        || BN_bn2binpad(xA, buf, p_bytes) < 0
        || !EVP_DigestUpdate(hash, buf, p_bytes)
        || BN_bn2binpad(yA, buf, p_bytes) < 0
        || !EVP_DigestUpdate(hash, buf, p_bytes)
        || !EVP_DigestFinal(hash, out, NULL)) {
        SM2err(SM2_F_SM2_COMPUTE_Z_DIGEST, ERR_R_INTERNAL_ERROR);
        goto done;
    }

    rc = 1;

done:
    OPENSSL_free(buf);
    BN_CTX_free(ctx);
    EVP_MD_CTX_free(hash);
    return rc;
}


void MainWindow::on_pushButton_sm3_hash_ZA_clicked()
{

    QString pubkeyStr = ui->textEdit_sm2_pubkey->toPlainText().remove(QRegularExpression("\\s")); // 清除空格或换行符
    QString uidStr = ui->textEdit_sm3_userid->toPlainText().remove(QRegularExpression("\\s")); // 清除空格或换行符
    QString hash_str = ui->textEdit_sm3_plain->toPlainText().remove(QRegularExpression("\\s")); // 清除空格或换行符
    QString hash_result = NULL;
    QString za_str = NULL;

    qDebug() << "Public Key:" << pubkeyStr;
    qDebug() << "User ID:" << uidStr;
    qDebug() << "Hash:" << hash_str;

    QByteArray pubkeyBytes = QByteArray::fromHex(pubkeyStr.toUtf8());
    QByteArray uidBytes = QByteArray::fromHex(uidStr.toUtf8());
    QByteArray hashBytes = QByteArray::fromHex(hash_str.toUtf8());

    const EVP_MD *digest_md = EVP_sm3();
    const int md_size = EVP_MD_size(digest_md);

    uint8_t *za = NULL;
    uint8_t *e = NULL;
    EC_KEY *ec_key = NULL;
    EVP_MD_CTX *hash = NULL;


    za = (uint8_t *)OPENSSL_malloc(md_size);
    if (za == NULL) {
        qDebug() << "Failed to allocate memory for ZA.";
        goto out;
    }

    e = (uint8_t *)OPENSSL_malloc(md_size);
    if (e == NULL) {
        qDebug() << "Failed to allocate memory for E.";
        goto out;
    }

    ec_key = EC_KEY_new_by_curve_name(NID_sm2);
    if (ec_key == NULL) {
        qDebug() << "Failed to create EC_KEY.";
        goto out;
    }

    if (EC_KEY_oct2key(ec_key, (const unsigned char *)pubkeyBytes.constData(), pubkeyBytes.size(), NULL) != 1) {
        qDebug() << "Failed to set public key to EC_KEY.";
        goto out;
    }

    if (!sm2_compute_z_digest(za, digest_md, (const uint8_t *)uidBytes.constData(), uidBytes.size(), ec_key)) {
        qDebug() << "Failed to compute ZA digest.";
        goto out;
    }

    za_str = QByteArray(reinterpret_cast<char *>(za), md_size).toHex();
    qDebug() << "ZA:" << za_str;

    hash = EVP_MD_CTX_new();

    if (!EVP_DigestInit(hash, digest_md)
        || !EVP_DigestUpdate(hash, za, md_size)
        || !EVP_DigestUpdate(hash, hashBytes.constData(), hashBytes.size())
        /* reuse z buffer to hold H(Z || M) */
        || !EVP_DigestFinal(hash, za, NULL)) {
        SM2err(SM2_F_SM2_COMPUTE_MSG_HASH, ERR_R_EVP_LIB);
        goto out;
    }


    hash_result = QByteArray(reinterpret_cast<char *>(za), md_size).toHex();

    qDebug() << "Hash:" << hash_result;

    ui->textEdit_sm3_hash_result->setText(hash_result);



out:
    if (za) {
        OPENSSL_free(za);
    }
    if (e) {
        OPENSSL_free(e);
    }
    if (ec_key) {
        EC_KEY_free(ec_key);
    }

}


void MainWindow::on_pushButton_sm2_tab_clear_clicked()
{
    ui->textEdit_sm2_prikey->clear();
    ui->textEdit_sm2_pubkey->clear();
    ui->textEdit_sm2_sign_data->clear();
    ui->textEdit_sm2_sign_value->clear();
    ui->textEdit_sm2_verify_result->clear();
    ui->textEdit_sm2_encrypt_plain->clear();
    ui->textEdit_sm2_encrypt_result->clear();
    ui->textEdit_sm2_decrypt_plain->clear();
    ui->textEdit_sm2_decrypt_result->clear();
}


void MainWindow::on_pushButton_sm3_tab_clear_clicked()
{
    ui->textEdit_sm3_userid->clear();
    ui->textEdit_sm3_plain->clear();
    ui->textEdit_sm3_hash_result->clear();
    ui->textEdit_sm3_publickey->clear();
}


void MainWindow::on_pushButton_sm4_encrypt_clicked()
{
    QString keyStr = ui->textEdit_sm4_key->toPlainText().remove(QRegularExpression("\\s")); // 清除空格或换行符
    QString plaintextStr = ui->textEdit_sm4_input->toPlainText().remove(QRegularExpression("\\s")); // 清除空格或换行符
    QString ivStr = ui->textEdit_sm4_iv->toPlainText().remove(QRegularExpression("\\s")); // 清除空格或换行符
    QString aadStr = ui->textEdit_sm4_aad->toPlainText().remove(QRegularExpression("\\s")); // 清除空格或换行符
    QString modeStr = ui->comboBox_sm4_mode->currentText();

    qDebug() << "Key:" << keyStr;
    qDebug() << "Plaintext:" << plaintextStr;
    qDebug() << "IV:" << ivStr;
    qDebug() << "AAD:" << aadStr;
    qDebug() << "Mode:" << modeStr;

    QString ciphertextStr = NULL;

    EVP_CIPHER_CTX *ctx = NULL;
    EVP_CIPHER *cipher = NULL;

    QByteArray keyBytes = QByteArray::fromHex(keyStr.toUtf8());
    QByteArray plaintextBytes = QByteArray::fromHex(plaintextStr.toUtf8());
    QByteArray ivBytes = QByteArray::fromHex(ivStr.toUtf8());
    QByteArray aadBytes = QByteArray::fromHex(aadStr.toUtf8());


    unsigned char *ciphertext = NULL;
    size_t ciphertext_len = 0;
    size_t tmp_len = 0;
    unsigned char tag[16];

    EVP_CIPHER *other_cipher = NULL;

    ciphertext = (unsigned char *)OPENSSL_malloc(plaintextBytes.size());
    if (!ciphertext) {
        qDebug() << "Failed to allocate memory for ciphertext.";
        goto out;
    }

    ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        qDebug() << "Failed to create EVP_CIPHER_CTX.";
        goto out;
    }

    if (modeStr == "ECB") {
        if (EVP_CipherInit(ctx, EVP_sm4_ecb(), (const unsigned char *)keyBytes.constData(), NULL, 1) != 1) {
            qDebug() << "Failed to set key.";
            goto out;
        }
    } else if (modeStr == "CBC") {
        if (EVP_CipherInit(ctx, EVP_sm4_cbc(), (const unsigned char *)keyBytes.constData(), (const unsigned char *)ivBytes.constData(), 1) != 1) {
            qDebug() << "Failed to set key and IV.";
            goto out;
        }
    } else if (modeStr == "CFB") {
        if (EVP_CipherInit(ctx, EVP_sm4_cfb(), (const unsigned char *)keyBytes.constData(), (const unsigned char *)ivBytes.constData(), 1) != 1) {
            qDebug() << "Failed to set key and IV.";
            goto out;
        }
    } else if (modeStr == "OFB") {
        if (EVP_CipherInit(ctx, EVP_sm4_ofb(), (const unsigned char *)keyBytes.constData(), (const unsigned char *)ivBytes.constData(), 1) != 1) {
            qDebug() << "Failed to set key and IV.";
            goto out;
        }
    } else if (modeStr == "CTR") {
        if (EVP_CipherInit(ctx, EVP_sm4_ctr(), (const unsigned char *)keyBytes.constData(), (const unsigned char *)ivBytes.constData(), 1) != 1) {
            qDebug() << "Failed to set key and IV.";
            goto out;
        }
    } else if (modeStr == "GCM") {
        other_cipher = EVP_CIPHER_fetch(NULL, "SM4-GCM", NULL);
        if (!other_cipher) {
            qDebug() << "Failed to fetch cipher. SM4-GCM";
            goto out;
        }
        if (EVP_CipherInit(ctx, other_cipher, NULL, NULL, 1) != 1) {
            qDebug() << "Failed to set key and IV.";
            goto out;
        }
        // if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, 12, NULL) != 1) {
        //     qDebug() << "Failed to set IV.";
        //     goto out;
        // }
        // if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, 16, NULL) != 1) {
        //     qDebug() << "Failed to set tag.";
        //     goto out;
        // }
        if (EVP_CipherInit(ctx, NULL, (const unsigned char *)keyBytes.constData(), (const unsigned char *)ivBytes.constData(), 1) != 1) {
            qDebug() << "Failed to set key and IV.";
            goto out;
        }
        if (EVP_CipherUpdate(ctx, NULL, (int *)&tmp_len, (const unsigned char *)aadBytes.constData(), aadBytes.size()) != 1) {
            qDebug() << "Failed to set AAD.";
            goto out;
        }

    } else if (modeStr == "CCM") {
        other_cipher = EVP_CIPHER_fetch(NULL, "SM4-CCM", NULL);
        if (!other_cipher) {
            qDebug() << "Failed to fetch cipher. SM4-CCM";
            goto out;
        }
        if (EVP_CipherInit(ctx, other_cipher, NULL, NULL, 1) != 1) {
            qDebug() << "Failed to set key and IV.";
            goto out;
        }
        if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_CCM_SET_IVLEN, 12, NULL) != 1) {
            qDebug() << "Failed to set IV.";
            goto out;
        }
        if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_CCM_SET_TAG, 16, NULL) != 1) {
            qDebug() << "Failed to set tag.";
            goto out;
        }
        // if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_CCM_SET_MSGLEN, plaintextBytes.size(), NULL) != 1) {
        //     qDebug() << "Failed to set message length.";
        //     goto out;
        // }
        if (EVP_CipherInit(ctx, NULL, (const unsigned char *)keyBytes.constData(), (const unsigned char *)ivBytes.constData(), 1) != 1) {
            qDebug() << "Failed to set key and IV.";
            goto out;
        }
        if (EVP_CipherUpdate(ctx, NULL, (int *)&tmp_len, NULL, plaintextBytes.size()) != 1) {
            qDebug() << "Failed to set message length.";
            goto out;
        }
        if (EVP_CipherUpdate(ctx, NULL, (int *)&tmp_len, (const unsigned char *)aadBytes.constData(), aadBytes.size()) != 1) {
            qDebug() << "Failed to set AAD.";
            goto out;
        }
    } else if (modeStr == "XTS") {
        other_cipher = EVP_CIPHER_fetch(NULL, "SM4-XTS", NULL);
        if (!other_cipher) {
            qDebug() << "Failed to fetch cipher. SM4-XTS";
            goto out;
        }
        if (EVP_CipherInit(ctx, other_cipher, (const unsigned char *)keyBytes.constData(), (const unsigned char *)ivBytes.constData(), 1) != 1) {
            qDebug() << "Failed to set key and IV.";
            goto out;
        }
    } else {
        qDebug() << "Unsupported mode.";
        goto out;
    }

    // 禁用补位
    EVP_CIPHER_CTX_set_padding(ctx, 0);

    if (EVP_CipherUpdate(ctx, ciphertext, (int *)&tmp_len, (const unsigned char *)plaintextBytes.constData(), plaintextBytes.size()) != 1) {
        qDebug() << "Failed to encrypt plaintext.";
        goto out;
    }
    qDebug() << "tmp_len:" << tmp_len;
    ciphertext_len += tmp_len;

    if (EVP_CipherFinal(ctx, ciphertext + tmp_len, (int *)&tmp_len) != 1) {
        qDebug() << "Failed to finalize encryption.";
        goto out;
    }
    qDebug() << "tmp_len:" << tmp_len;
    ciphertext_len += tmp_len;


    ciphertextStr = QByteArray(reinterpret_cast<char *>(ciphertext), ciphertext_len).toHex();

    qDebug() << "Ciphertext:" << ciphertextStr;

    ui->textEdit_sm4_output->setText(ciphertextStr);


    if (modeStr == "GCM") {
        if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, 16, tag) != 1) {
            qDebug() << "Failed to get tag.";
            goto out;
        }
        QString tagStr = QByteArray(reinterpret_cast<char *>(tag), 16).toHex();
        qDebug() << "Tag:" << tagStr;
        ui->textEdit_sm4_output_tag->setText(tagStr);
    }
    if (modeStr == "CCM") {
        if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_CCM_GET_TAG, 16, tag) != 1) {
            qDebug() << "Failed to get tag.";
            goto out;
        }
        QString tagStr = QByteArray(reinterpret_cast<char *>(tag), 16).toHex();
        qDebug() << "Tag:" << tagStr;
        ui->textEdit_sm4_output_tag->setText(tagStr);
    }


out:
    if (ciphertext) {
        OPENSSL_free(ciphertext);
    }
    if (ctx) {
        EVP_CIPHER_CTX_free(ctx);
    }
}


void MainWindow::on_pushButton_gen_rsa_keypair_clicked()
{
    EVP_PKEY *pkey = NULL;
    EVP_PKEY_CTX *pctx = NULL;

    int rsa_key_len = 2048;

    RSA *rsa = NULL;

    BIGNUM *n = NULL;
    BIGNUM *e = NULL;
    BIGNUM *d = NULL;
    BIGNUM *p = NULL;
    BIGNUM *q = NULL;
    BIGNUM *dmp1 = NULL;
    BIGNUM *dmq1 = NULL;
    BIGNUM *iqmp = NULL;

    char *n_hex = NULL;
    char *e_hex = NULL;
    char *d_hex = NULL;
    char *p_hex = NULL;
    char *q_hex = NULL;
    char *dmp1_hex = NULL;
    char *dmq1_hex = NULL;
    char *iqmp_hex = NULL;

    QString nStr = NULL;
    QString eStr = NULL;
    QString dStr = NULL;
    QString pStr = NULL;
    QString qStr = NULL;
    QString dmp1Str = NULL;
    QString dmq1Str = NULL;
    QString iqmpStr = NULL;

    QString rsa_pubkey = NULL;
    QString rsa_prikey = NULL;

    pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, NULL);
    if (!pctx) {
        qDebug() << "Failed to create EVP_PKEY_CTX.";
        goto out;
    }

    if (EVP_PKEY_keygen_init(pctx) <= 0) {
        qDebug() << "Failed to initialize key generation.";
        goto out;
    }

    if (EVP_PKEY_CTX_set_rsa_keygen_bits(pctx, rsa_key_len) <= 0) {
        qDebug() << "Failed to set key length.";
        goto out;
    }

    if (EVP_PKEY_keygen(pctx, &pkey) <= 0) {
        qDebug() << "Failed to generate key pair.";
        goto out;
    }


    rsa = EVP_PKEY_get1_RSA(pkey);

    RSA_get0_key(rsa, (const BIGNUM **)&n, (const BIGNUM **)&e, (const BIGNUM **)&d);
    RSA_get0_factors(rsa, (const BIGNUM **)&p, (const BIGNUM **)&q);
    RSA_get0_crt_params(rsa, (const BIGNUM **)&dmp1, (const BIGNUM **)&dmq1, (const BIGNUM **)&iqmp);

    n_hex = BN_bn2hex(n);
    if (!n_hex) {
        qDebug() << "Failed to convert n to hex.";
        goto out;
    }
    nStr = n_hex;

    e_hex = BN_bn2hex(e);
    if (!e_hex) {
        qDebug() << "Failed to convert e to hex.";
        goto out;
    }
    eStr = e_hex;

    d_hex = BN_bn2hex(d);
    if (!d_hex) {
        qDebug() << "Failed to convert d to hex.";
        goto out;
    }
    dStr = d_hex;

    p_hex = BN_bn2hex(p);
    if (!p_hex) {
        qDebug() << "Failed to convert p to hex.";
        goto out;
    }
    pStr = p_hex;

    q_hex = BN_bn2hex(q);
    if (!q_hex) {
        qDebug() << "Failed to convert q to hex.";
        goto out;
    }
    qStr = q_hex;

    dmp1_hex = BN_bn2hex(dmp1);
    if (!dmp1_hex) {
        qDebug() << "Failed to convert dmp1 to hex.";
        goto out;
    }
    dmp1Str = dmp1_hex;

    dmq1_hex = BN_bn2hex(dmq1);
    if (!dmq1_hex) {
        qDebug() << "Failed to convert dmq1 to hex.";
        goto out;
    }
    dmq1Str = dmq1_hex;

    iqmp_hex = BN_bn2hex(iqmp);
    if (!iqmp_hex) {
        qDebug() << "Failed to convert iqmp to hex.";
        goto out;
    }
    iqmpStr = iqmp_hex;

    rsa_pubkey = nStr + eStr;
    rsa_prikey = nStr + dStr;

    ui->textEdit_rsa_pubkey->setText(rsa_pubkey);
    ui->textEdit_rsa_prikey->setText(rsa_prikey);

    // test RSA encryption and decryption
    if (0) {
        QByteArray plaintextBytes = "Hello, World!";
        QByteArray ciphertextBytes;
        QByteArray decryptBytes;
        QString ciphertextStr;
        QString decryptStr;

        unsigned char *ciphertext = NULL;
        size_t ciphertext_len = 0;
        unsigned char *decrypttext = NULL;
        size_t decrypt_len = 0;

        ciphertext = (unsigned char *)OPENSSL_malloc(RSA_size(rsa));
        if (!ciphertext) {
            qDebug() << "Failed to allocate memory for ciphertext.";
            goto out;
        }

        decrypttext = (unsigned char *)OPENSSL_malloc(RSA_size(rsa));
        if (!decrypttext) {
            qDebug() << "Failed to allocate memory for decrypttext.";
            goto out;
        }

        ciphertext_len = 2048 / 8;
        decrypt_len = 2048 / 8;

        RSA_public_encrypt(plaintextBytes.size(), (const unsigned char *)plaintextBytes.constData(), ciphertext, rsa, RSA_PKCS1_PADDING);

        ciphertextStr = QByteArray(reinterpret_cast<char *>(ciphertext), ciphertext_len).toHex();
        qDebug() << "Ciphertext:" << ciphertextStr;

        RSA_private_decrypt(decrypt_len, ciphertext, decrypttext, rsa, RSA_PKCS1_PADDING);

        decryptStr = QByteArray(reinterpret_cast<char *>(decrypttext), decrypt_len).toHex();
        qDebug() << "Decrypt:" << decryptStr;
        qDebug() << "Decrypt:" << QByteArray::fromHex(decryptStr.toUtf8());

    }



out:
    if (pkey) {
        EVP_PKEY_free(pkey);
    }
    if (pctx) {
        EVP_PKEY_CTX_free(pctx);
    }
    if (rsa) {
        RSA_free(rsa);
    }
    if (n_hex) {
        OPENSSL_free(n_hex);
    }
    if (e_hex) {
        OPENSSL_free(e_hex);
    }
    if (d_hex) {
        OPENSSL_free(d_hex);
    }
    if (p_hex) {
        OPENSSL_free(p_hex);
    }
    if (q_hex) {
        OPENSSL_free(q_hex);
    }
    if (dmp1_hex) {
        OPENSSL_free(dmp1_hex);
    }
    if (dmq1_hex) {
        OPENSSL_free(dmq1_hex);
    }
    if (iqmp_hex) {
        OPENSSL_free(iqmp_hex);
    }

}


void MainWindow::on_pushButton_rsa_prikey_operation_clicked()
{
    QString prikeyStr = ui->textEdit_rsa_prikey->toPlainText().remove(QRegularExpression("\\s")); // 清除空格或换行符
    QString decryptPlainStr = ui->textEdit_rsa_decrypt_plain->toPlainText().remove(QRegularExpression("\\s")); // 清除空格或换行符
    QString eStr = "010001";
    QString decryptResultStr = NULL;

    qDebug() << "Private Key:" << prikeyStr;
    qDebug() << "decryptPlainStr:" << decryptPlainStr;

    int rsa_key_len = 2048;
    QByteArray prikeyBytes = QByteArray::fromHex(prikeyStr.toUtf8());
    QByteArray decryptPlainBytes = QByteArray::fromHex(decryptPlainStr.toUtf8());
    QByteArray eBytes = QByteArray::fromHex(eStr.toUtf8());

    unsigned char *n_bytes = NULL;
    unsigned char *d_bytes = NULL;

    RSA *rsa = NULL;
    BIGNUM *n = NULL;
    BIGNUM *d = NULL;
    BIGNUM *e = NULL;
    EVP_PKEY *pkey = NULL;
    EVP_PKEY_CTX *pkctx = NULL;
    size_t decrypt_len = 0;
    unsigned char *decrypt_result = NULL;

    // int e_num = 65537;


    n_bytes = (unsigned char *)OPENSSL_malloc(rsa_key_len / 8);
    if (!n_bytes) {
        qDebug() << "Failed to allocate memory for n.";
        goto out;
    }
    d_bytes = (unsigned char *)OPENSSL_malloc(rsa_key_len / 8);
    if (!d_bytes) {
        qDebug() << "Failed to allocate memory for d.";
        goto out;
    }

    memcpy(n_bytes, prikeyBytes.constData(), rsa_key_len / 8);
    memcpy(d_bytes, prikeyBytes.constData() + rsa_key_len / 8, rsa_key_len / 8);

    rsa = RSA_new();
    if (!rsa) {
        qDebug() << "Failed to create RSA.";
        goto out;
    }

    n = BN_bin2bn(n_bytes, rsa_key_len / 8, NULL);
    d = BN_bin2bn(d_bytes, rsa_key_len / 8, NULL);
    e = BN_bin2bn((const unsigned char *)eBytes.constData(), eBytes.size(), NULL);
    if (!n || !d) {
        qDebug() << "Failed to convert n or d.";
        goto out;
    }

    if (RSA_set0_key(rsa, n, e, d) != 1) {
        qDebug() << "Failed to set key to RSA.";
        goto out;
    }

    pkey = EVP_PKEY_new();
    if (!pkey) {
        qDebug() << "Failed to create EVP_PKEY.";
        goto out;
    }

    if (EVP_PKEY_set1_RSA(pkey, rsa) != 1) {
        qDebug() << "Failed to assign RSA to EVP_PKEY.";
        goto out;
    }

    pkctx = EVP_PKEY_CTX_new(pkey, NULL);
    if (!pkctx) {
        qDebug() << "Failed to create EVP_PKEY_CTX.";
        goto out;
    }

    if (EVP_PKEY_decrypt_init(pkctx) <= 0) {
        qDebug() << "Failed to initialize decryption, Error String:" << ERR_error_string(ERR_get_error(), NULL);
        goto out;
    }

    if (EVP_PKEY_CTX_set_rsa_padding(pkctx, RSA_PKCS1_PADDING) <= 0) {
        qDebug() << "Failed to set padding.";
        goto out;
    }

    if (EVP_PKEY_decrypt(pkctx, NULL, &decrypt_len, (const unsigned char *)decryptPlainBytes.constData(), decryptPlainBytes.size()) <= 0) {
        qDebug() << "Failed to decrypt.";
        goto out;
    }

    qDebug() << "decrypt_len:" << decrypt_len;

    decrypt_result = (unsigned char *)OPENSSL_malloc(decrypt_len);
    if (!decrypt_result) {
        qDebug() << "Failed to allocate memory for decrypt_result.";
        goto out;
    }

    if (EVP_PKEY_decrypt(pkctx, decrypt_result, &decrypt_len, (const unsigned char *)decryptPlainBytes.constData(), decryptPlainBytes.size()) <= 0) {
        qDebug() << "Failed to decrypt.";
        goto out;
    }

    qDebug() << "decrypt_len:" << decrypt_len;

    decryptResultStr = QByteArray(reinterpret_cast<char *>(decrypt_result), decrypt_len).toHex();

    qDebug() << "decryptResultStr:" << decryptResultStr;

    ui->textEdit_rsa_decrypt_result->setText(decryptResultStr);


out:
    if (n_bytes) {
        OPENSSL_free(n_bytes);
    }
    if (d_bytes) {
        OPENSSL_free(d_bytes);
    }
    if (decrypt_result) {
        OPENSSL_free(decrypt_result);
    }
    if (rsa) {
        RSA_free(rsa); // 自动释放 n, e, d
    }
    if (pkctx) {
        EVP_PKEY_CTX_free(pkctx);
        pkctx = NULL;
    }
    if (pkey) {
        EVP_PKEY_free(pkey);
        pkey = NULL;
    }
}


void MainWindow::on_pushButton_rsa_pubkey_operation_clicked()
{
    QString pubkeyStr = ui->textEdit_rsa_pubkey->toPlainText().remove(QRegularExpression("\\s")); // 清除空格或换行符
    QString privateKeyStr = ui->textEdit_rsa_prikey->toPlainText().remove(QRegularExpression("\\s")); // 清除空格或换行符
    QString encryptPlainStr = ui->textEdit_rsa_encrypt_plain->toPlainText().remove(QRegularExpression("\\s")); // 清除空格或换行符
    QString encryptResultStr = NULL;

    qDebug() << "Public Key:" << pubkeyStr;
    qDebug() << "encryptPlainStr:" << encryptPlainStr;

    QByteArray pubkeyBytes = QByteArray::fromHex(pubkeyStr.toUtf8());
    QByteArray privateKeyBytes = QByteArray::fromHex(privateKeyStr.toUtf8());
    QByteArray encryptPlainBytes = QByteArray::fromHex(encryptPlainStr.toUtf8());

    int rsa_key_len = 2048;

    unsigned char *n_bytes = NULL;
    unsigned char *e_bytes = NULL;
    int e_num = 65537;

    RSA *rsa = NULL;
    BIGNUM *n = NULL;
    BIGNUM *e = NULL;
    BIGNUM *d = NULL;
    EVP_PKEY *pkey = NULL;
    EVP_PKEY_CTX *pkctx = NULL;
    int ret = 0;
    int e_len = 0;
    unsigned char *encrypt_result = NULL;
    size_t encrypt_len = 0;

    n_bytes = (unsigned char *)OPENSSL_malloc(rsa_key_len / 8);
    if (!n_bytes) {
        qDebug() << "Failed to allocate memory for n.";
        goto out;
    }

    e_len = pubkeyBytes.size() - rsa_key_len / 8;
    qDebug() << "e_len:" << e_len;

    e_bytes = (unsigned char *)OPENSSL_malloc(e_len);
    if (!e_bytes) {
        qDebug() << "Failed to allocate memory for e.";
        goto out;
    }

    memcpy(n_bytes, pubkeyBytes.constData(), rsa_key_len / 8);
    memcpy(e_bytes, pubkeyBytes.constData() + rsa_key_len / 8, e_len);

    rsa = RSA_new();
    if (!rsa) {
        qDebug() << "Failed to create RSA.";
        goto out;
    }

    n = BN_bin2bn(n_bytes, rsa_key_len / 8, NULL);
    e = BN_bin2bn(e_bytes, e_len, NULL);
    d = BN_bin2bn((const unsigned char *)privateKeyBytes.constData() + rsa_key_len / 8, rsa_key_len / 8, NULL);
    if (!n || !e) {
        qDebug() << "Failed to convert n or e.";
        goto out;
    }

    pkey = EVP_PKEY_new();
    if (!pkey) {
        qDebug() << "Failed to create EVP_PKEY.";
        goto out;
    }

    if (RSA_set0_key(rsa, n, e, d) != 1) {
        qDebug() << "Failed to set key to RSA.";
        goto out;
    }

    if (EVP_PKEY_set1_RSA(pkey, rsa) != 1) {
        qDebug() << "Failed to assign RSA to EVP_PKEY.";
        goto out;
    }

    pkctx = EVP_PKEY_CTX_new(pkey, NULL);
    if (!pkctx) {
        qDebug() << "Failed to create EVP_PKEY_CTX.";
        goto out;
    }

    if (EVP_PKEY_encrypt_init(pkctx) <= 0) {
        qDebug() << "Failed to initialize encryption.";
        goto out;
    }

    if (EVP_PKEY_CTX_set_rsa_padding(pkctx, RSA_PKCS1_PADDING) <= 0) {
        qDebug() << "Failed to set padding.";
        goto out;
    }

    if (EVP_PKEY_encrypt(pkctx, NULL, &encrypt_len, (const unsigned char *)encryptPlainBytes.constData(), encryptPlainBytes.size()) <= 0) {
        qDebug() << "Failed to encrypt.";
        goto out;
    }

    qDebug() << "encrypt_len:" << encrypt_len;

    encrypt_result = (unsigned char *)OPENSSL_malloc(encrypt_len);
    if (encrypt_result == NULL) {
        qDebug() << "Failed to allocate memory for encrypt_result.";
        goto out;
    }

    if (EVP_PKEY_encrypt(pkctx, encrypt_result, &encrypt_len, (const unsigned char *)encryptPlainBytes.constData(), encryptPlainBytes.size()) <= 0) {
        qDebug() << "Failed to encrypt.";
        goto out;
    }

    qDebug() << "encrypt_len:" << encrypt_len;

    encryptResultStr = QByteArray(reinterpret_cast<char *>(encrypt_result), encrypt_len).toHex();

    qDebug() << "encryptResultStr:" << encryptResultStr;

    ui->textEdit_rsa_encrypt_result->setText(encryptResultStr);

out:
    if (encrypt_result) {
        OPENSSL_free(encrypt_result);
    }
    if (n_bytes) {
        OPENSSL_free(n_bytes);
    }
    if (e_bytes) {
        OPENSSL_free(e_bytes);
    }
    if (rsa) {
        RSA_free(rsa); // 自动释放 n, e, d
    }
    if (pkey) {
        EVP_PKEY_free(pkey);
    }
    if (pkctx) {
        EVP_PKEY_CTX_free(pkctx);
    }
}

