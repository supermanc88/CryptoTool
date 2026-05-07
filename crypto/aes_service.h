#ifndef CRYPTO_AES_SERVICE_H
#define CRYPTO_AES_SERVICE_H

#include "shared/crypto_common.h"

namespace Crypto::AesService {

OperationResult process(const QString &keyHex,
                        const QString &inputHex,
                        const QString &ivHex,
                        const QString &aadHex,
                        const QString &tagHex,
                        const QString &mode,
                        const QString &padding,
                        bool encryptMode);

} // namespace Crypto::AesService

#endif // CRYPTO_AES_SERVICE_H
