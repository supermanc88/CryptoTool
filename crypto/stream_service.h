#ifndef CRYPTO_STREAM_SERVICE_H
#define CRYPTO_STREAM_SERVICE_H

#include "shared/crypto_common.h"

namespace Crypto::StreamService {

OperationResult process(const QString &mode,
                        const QString &keyHex,
                        const QString &inputHex,
                        const QString &ivHex,
                        bool encryptMode);

} // namespace Crypto::StreamService

#endif
