#ifndef CRYPTO_DIGEST_SERVICE_H
#define CRYPTO_DIGEST_SERVICE_H

#include "shared/crypto_common.h"

namespace Crypto::DigestService {

OperationResult calculate(const QString &digestName, const QString &plainHex);

} // namespace Crypto::DigestService

#endif
