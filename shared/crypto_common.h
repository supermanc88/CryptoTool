#ifndef SHARED_CRYPTO_COMMON_H
#define SHARED_CRYPTO_COMMON_H

#include <QString>
#include <QStringList>
#include <QByteArray>

#include <openssl/bn.h>
#include <openssl/evp.h>

namespace Crypto {

struct OperationResult
{
    bool success = false;
    QString primaryText;
    QString secondaryText;
    QString tertiaryText;
    QString message;
};

struct KeyPairResult
{
    bool success = false;
    QString publicKey;
    QString privateKey;
    QString message;
};

struct DsaKeyPairResult
{
    bool success = false;
    QString publicKey;
    QString privateKey;
    QString p;
    QString q;
    QString g;
    QString message;
};

QString normalizeHex(const QString &text);
QByteArray parseInput(const QString &text, const QString &inputType);
QString bnToHex(const BIGNUM *bn);
QString opensslError(const QString &fallback);
const EVP_MD *resolveDigest(const QString &name, bool *isXof = nullptr);

} // namespace Crypto

#endif
