#ifndef CRYPTO_SM2_SERVICE_H
#define CRYPTO_SM2_SERVICE_H

#include "shared/crypto_common.h"

namespace Crypto::Sm2Service {

KeyPairResult generateKeyPair();
OperationResult signHash(const QString &privateKeyHex, const QString &hashHex);
OperationResult verifySignature(const QString &publicKeyHex, const QString &hashHex, const QString &signatureHex);
OperationResult encrypt(const QString &publicKeyHex, const QString &plainHex);
OperationResult decrypt(const QString &privateKeyHex, const QString &cipherHex);
OperationResult derivePublicKey(const QString &privateKeyHex);
OperationResult hashWithZa(const QString &publicKeyHex,
                           const QString &userId,
                           const QString &userIdInputType,
                           const QString &plainText,
                           const QString &plainInputType);

} // namespace Crypto::Sm2Service

#endif
