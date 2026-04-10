#include "crypto/sm3_service.h"

#include <openssl/evp.h>

namespace Crypto::Sm3Service {

OperationResult hash(const QString &plainText, const QString &inputType)
{
    OperationResult result;
    QByteArray data = parseInput(plainText, inputType);
    EVP_MD_CTX *context = EVP_MD_CTX_new();
    unsigned char digest[32];
    unsigned int digestLen = sizeof(digest);

    if (!context
        || EVP_DigestInit(context, EVP_sm3()) != 1
        || EVP_DigestUpdate(context,
                            reinterpret_cast<const unsigned char *>(data.constData()),
                            data.size()) != 1
        || EVP_DigestFinal(context, digest, &digestLen) != 1) {
        result.message = opensslError("Failed to calculate SM3 hash.");
        EVP_MD_CTX_free(context);
        return result;
    }

    result.success = true;
    result.primaryText = QByteArray(reinterpret_cast<char *>(digest), digestLen).toHex();
    EVP_MD_CTX_free(context);
    return result;
}

} // namespace Crypto::Sm3Service
