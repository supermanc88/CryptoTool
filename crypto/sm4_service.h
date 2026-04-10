#ifndef CRYPTO_SM4_SERVICE_H
#define CRYPTO_SM4_SERVICE_H

#include "shared/crypto_common.h"

namespace Crypto::Sm4Service {

OperationResult process(const QString &keyHex,
                        const QString &inputHex,
                        const QString &ivHex,
                        const QString &aadHex,
                        const QString &mode,
                        const QString &padding,
                        bool encryptMode);

} // namespace Crypto::Sm4Service

#endif
