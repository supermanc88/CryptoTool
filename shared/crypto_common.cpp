#include "shared/crypto_common.h"

#include <QRegularExpression>

#include <openssl/err.h>

namespace Crypto {

QString normalizeHex(const QString &text)
{
    QString normalized = text;
    normalized.remove(QRegularExpression("\\s"));
    return normalized;
}

QByteArray parseInput(const QString &text, const QString &inputType)
{
    if (inputType.compare("String", Qt::CaseInsensitive) == 0) {
        return text.toUtf8();
    }

    return QByteArray::fromHex(normalizeHex(text).toUtf8());
}

QString bnToHex(const BIGNUM *bn)
{
    if (!bn) {
        return {};
    }

    char *hex = BN_bn2hex(bn);
    QString value = hex ? QString::fromLatin1(hex) : QString();
    if (hex) {
        OPENSSL_free(hex);
    }
    return value;
}

QString opensslError(const QString &fallback)
{
    unsigned long error = ERR_get_error();
    if (error == 0) {
        return fallback;
    }

    char buffer[256] = {0};
    ERR_error_string_n(error, buffer, sizeof(buffer));
    return QString::fromLatin1(buffer);
}

const EVP_MD *resolveDigest(const QString &name, bool *isXof)
{
    if (isXof) {
        *isXof = false;
    }

    if (name == "md4") return EVP_md4();
    if (name == "md5") return EVP_md5();
    if (name == "mdc2") return EVP_mdc2();
    if (name == "sha1") return EVP_sha1();
    if (name == "sha224") return EVP_sha224();
    if (name == "sha256") return EVP_sha256();
    if (name == "sha384") return EVP_sha384();
    if (name == "sha512") return EVP_sha512();
    if (name == "sha512-224") return EVP_sha512_224();
    if (name == "sha512-256") return EVP_sha512_256();
    if (name == "sha3-224") return EVP_sha3_224();
    if (name == "sha3-256") return EVP_sha3_256();
    if (name == "sha3-384") return EVP_sha3_384();
    if (name == "sha3-512") return EVP_sha3_512();
    if (name == "sm3") return EVP_sm3();
    if (name == "blake2b512") return EVP_blake2b512();
    if (name == "blake2s256") return EVP_blake2s256();
    if (name == "shake128") {
        if (isXof) *isXof = true;
        return EVP_shake128();
    }
    if (name == "shake256") {
        if (isXof) *isXof = true;
        return EVP_shake256();
    }
    return nullptr;
}

} // namespace Crypto
