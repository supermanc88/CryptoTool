#include "crypto/rsa_service.h"

#include <openssl/rsa.h>

namespace Crypto::RsaService {

KeyPairResult generateKeyPair(int keyBits)
{
    KeyPairResult result;
    EVP_PKEY *pkey = nullptr;
    EVP_PKEY_CTX *context = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, nullptr);

    if (!context
        || EVP_PKEY_keygen_init(context) <= 0
        || EVP_PKEY_CTX_set_rsa_keygen_bits(context, keyBits) <= 0
        || EVP_PKEY_keygen(context, &pkey) <= 0) {
        result.message = opensslError("Failed to generate RSA key pair.");
        EVP_PKEY_CTX_free(context);
        EVP_PKEY_free(pkey);
        return result;
    }

    RSA *rsa = EVP_PKEY_get1_RSA(pkey);
    const BIGNUM *n = nullptr;
    const BIGNUM *e = nullptr;
    const BIGNUM *d = nullptr;
    RSA_get0_key(rsa, &n, &e, &d);

    result.publicKey = bnToHex(n) + bnToHex(e);
    result.privateKey = bnToHex(n) + bnToHex(d);
    result.success = !result.publicKey.isEmpty() && !result.privateKey.isEmpty();
    if (!result.success) {
        result.message = "Failed to extract RSA key material.";
    }

    RSA_free(rsa);
    EVP_PKEY_CTX_free(context);
    EVP_PKEY_free(pkey);
    return result;
}

OperationResult decrypt(const QString &privateKeyHex, const QString &cipherHex)
{
    OperationResult result;
    QByteArray privateKeyBytes = QByteArray::fromHex(normalizeHex(privateKeyHex).toUtf8());
    QByteArray cipherBytes = QByteArray::fromHex(normalizeHex(cipherHex).toUtf8());
    const int keyBytes = privateKeyBytes.size() / 2;
    QByteArray nBytes = privateKeyBytes.left(keyBytes);
    QByteArray dBytes = privateKeyBytes.mid(keyBytes);
    QByteArray eBytes = QByteArray::fromHex("010001");

    RSA *rsa = RSA_new();
    BIGNUM *n = BN_bin2bn(reinterpret_cast<const unsigned char *>(nBytes.constData()), nBytes.size(), nullptr);
    BIGNUM *d = BN_bin2bn(reinterpret_cast<const unsigned char *>(dBytes.constData()), dBytes.size(), nullptr);
    BIGNUM *e = BN_bin2bn(reinterpret_cast<const unsigned char *>(eBytes.constData()), eBytes.size(), nullptr);
    EVP_PKEY *pkey = EVP_PKEY_new();
    EVP_PKEY_CTX *context = nullptr;
    unsigned char *plain = nullptr;
    size_t plainLen = 0;

    if (!rsa || !n || !d || !e || !pkey
        || RSA_set0_key(rsa, n, e, d) != 1
        || EVP_PKEY_set1_RSA(pkey, rsa) != 1
        || !(context = EVP_PKEY_CTX_new(pkey, nullptr))
        || EVP_PKEY_decrypt_init(context) <= 0
        || EVP_PKEY_CTX_set_rsa_padding(context, RSA_PKCS1_PADDING) <= 0
        || EVP_PKEY_decrypt(context, nullptr, &plainLen,
                            reinterpret_cast<const unsigned char *>(cipherBytes.constData()),
                            cipherBytes.size()) <= 0) {
        result.message = opensslError("Failed to initialize RSA decryption.");
        goto out;
    }

    plain = static_cast<unsigned char *>(OPENSSL_malloc(plainLen));
    if (!plain
        || EVP_PKEY_decrypt(context,
                            plain,
                            &plainLen,
                            reinterpret_cast<const unsigned char *>(cipherBytes.constData()),
                            cipherBytes.size()) <= 0) {
        result.message = opensslError("Failed to decrypt RSA ciphertext.");
        goto out;
    }

    result.success = true;
    result.primaryText = QByteArray(reinterpret_cast<char *>(plain), plainLen).toHex();

out:
    OPENSSL_free(plain);
    EVP_PKEY_CTX_free(context);
    EVP_PKEY_free(pkey);
    RSA_free(rsa);
    return result;
}

OperationResult encrypt(const QString &publicKeyHex, const QString &privateKeyHex, const QString &plainHex)
{
    OperationResult result;
    QByteArray publicKeyBytes = QByteArray::fromHex(normalizeHex(publicKeyHex).toUtf8());
    QByteArray privateKeyBytes = QByteArray::fromHex(normalizeHex(privateKeyHex).toUtf8());
    QByteArray plainBytes = QByteArray::fromHex(normalizeHex(plainHex).toUtf8());

    const int nSize = privateKeyBytes.size() / 2;
    QByteArray nBytes = publicKeyBytes.left(nSize);
    QByteArray eBytes = publicKeyBytes.mid(nSize);
    QByteArray dBytes = privateKeyBytes.mid(nSize);

    RSA *rsa = RSA_new();
    BIGNUM *n = BN_bin2bn(reinterpret_cast<const unsigned char *>(nBytes.constData()), nBytes.size(), nullptr);
    BIGNUM *e = BN_bin2bn(reinterpret_cast<const unsigned char *>(eBytes.constData()), eBytes.size(), nullptr);
    BIGNUM *d = BN_bin2bn(reinterpret_cast<const unsigned char *>(dBytes.constData()), dBytes.size(), nullptr);
    EVP_PKEY *pkey = EVP_PKEY_new();
    EVP_PKEY_CTX *context = nullptr;
    unsigned char *cipher = nullptr;
    size_t cipherLen = 0;

    if (!rsa || !n || !e || !d || !pkey
        || RSA_set0_key(rsa, n, e, d) != 1
        || EVP_PKEY_set1_RSA(pkey, rsa) != 1
        || !(context = EVP_PKEY_CTX_new(pkey, nullptr))
        || EVP_PKEY_encrypt_init(context) <= 0
        || EVP_PKEY_CTX_set_rsa_padding(context, RSA_PKCS1_PADDING) <= 0
        || EVP_PKEY_encrypt(context, nullptr, &cipherLen,
                            reinterpret_cast<const unsigned char *>(plainBytes.constData()),
                            plainBytes.size()) <= 0) {
        result.message = opensslError("Failed to initialize RSA encryption.");
        goto out;
    }

    cipher = static_cast<unsigned char *>(OPENSSL_malloc(cipherLen));
    if (!cipher
        || EVP_PKEY_encrypt(context,
                            cipher,
                            &cipherLen,
                            reinterpret_cast<const unsigned char *>(plainBytes.constData()),
                            plainBytes.size()) <= 0) {
        result.message = opensslError("Failed to encrypt RSA plaintext.");
        goto out;
    }

    result.success = true;
    result.primaryText = QByteArray(reinterpret_cast<char *>(cipher), cipherLen).toHex();

out:
    OPENSSL_free(cipher);
    EVP_PKEY_CTX_free(context);
    EVP_PKEY_free(pkey);
    RSA_free(rsa);
    return result;
}

} // namespace Crypto::RsaService
