#ifndef CRYPTO_SM3_SERVICE_H
#define CRYPTO_SM3_SERVICE_H

#include "shared/crypto_common.h"

namespace Crypto::Sm3Service {

OperationResult hash(const QString &plainText, const QString &inputType);

} // namespace Crypto::Sm3Service

#endif
