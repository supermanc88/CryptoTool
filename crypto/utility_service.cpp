#include "crypto/utility_service.h"

namespace Crypto::UtilityService {

OperationResult xorHex(const QString &leftHex, const QString &rightHex)
{
    OperationResult result;
    QByteArray leftBytes = QByteArray::fromHex(normalizeHex(leftHex).toUtf8());
    QByteArray rightBytes = QByteArray::fromHex(normalizeHex(rightHex).toUtf8());

    if (leftBytes.size() != rightBytes.size()) {
        result.message = "Input size not equal.";
        return result;
    }

    QByteArray output(leftBytes.size(), '\0');
    for (int i = 0; i < leftBytes.size(); ++i) {
        output[i] = leftBytes[i] ^ rightBytes[i];
    }

    result.success = true;
    result.primaryText = output.toHex();
    return result;
}

} // namespace Crypto::UtilityService
