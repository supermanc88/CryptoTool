#ifndef CRYPTO_MAC_SERVICE_H
#define CRYPTO_MAC_SERVICE_H

#include "shared/crypto_common.h"

namespace Crypto::MacService {

OperationResult calculate(const QString &macMode,
                          const QString &internalMode,
                          const QString &keyHex,
                          const QString &plainHex);
QStringList internalModes(const QString &macMode);

} // namespace Crypto::MacService

#endif
