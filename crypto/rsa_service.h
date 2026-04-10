#ifndef CRYPTO_RSA_SERVICE_H
#define CRYPTO_RSA_SERVICE_H

#include "shared/crypto_common.h"

namespace Crypto::RsaService {

KeyPairResult generateKeyPair(int keyBits);
OperationResult encrypt(const QString &publicKeyHex, const QString &privateKeyHex, const QString &plainHex);
OperationResult decrypt(const QString &privateKeyHex, const QString &cipherHex);

} // namespace Crypto::RsaService

#endif
