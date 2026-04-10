#ifndef CRYPTO_DSA_SERVICE_H
#define CRYPTO_DSA_SERVICE_H

#include "shared/crypto_common.h"

namespace Crypto::DsaService {

DsaKeyPairResult generateKeyPair();
OperationResult sign(const QString &publicKeyHex,
                     const QString &privateKeyHex,
                     const QString &dataHex,
                     const QString &pHex,
                     const QString &qHex,
                     const QString &gHex,
                     const QString &digestName);
OperationResult verify(const QString &publicKeyHex,
                       const QString &dataHex,
                       const QString &signatureHex,
                       const QString &pHex,
                       const QString &qHex,
                       const QString &gHex,
                       const QString &digestName);

} // namespace Crypto::DsaService

#endif
