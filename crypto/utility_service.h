#ifndef CRYPTO_UTILITY_SERVICE_H
#define CRYPTO_UTILITY_SERVICE_H

#include "shared/crypto_common.h"

namespace Crypto::UtilityService {

OperationResult xorHex(const QString &leftHex, const QString &rightHex);

} // namespace Crypto::UtilityService

#endif
