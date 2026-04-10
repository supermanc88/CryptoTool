#include "crypto/digest_service.h"

namespace Crypto::DigestService {

OperationResult calculate(const QString &digestName, const QString &plainHex)
{
    OperationResult result;
    bool isXof = false;
    const EVP_MD *digest = resolveDigest(digestName, &isXof);
    if (!digest) {
        result.message = "Unsupported digest mode.";
        return result;
    }

    QByteArray dataBytes = QByteArray::fromHex(normalizeHex(plainHex).toUtf8());
    EVP_MD_CTX *context = EVP_MD_CTX_new();
    unsigned char *output = static_cast<unsigned char *>(OPENSSL_malloc(1024));
    size_t outputLen = 1024;
    unsigned int digestLen = 0;

    if (!context || !output
        || EVP_DigestInit(context, digest) <= 0
        || EVP_DigestUpdate(context,
                            reinterpret_cast<const unsigned char *>(dataBytes.constData()),
                            dataBytes.size()) <= 0) {
        result.message = opensslError("Failed to initialize digest calculation.");
        goto out;
    }

    if (isXof) {
        if (EVP_DigestFinalXOF(context, output, outputLen) <= 0) {
            result.message = opensslError("Failed to finalize XOF digest.");
            goto out;
        }
    } else {
        if (EVP_DigestFinal(context, output, &digestLen) <= 0) {
            result.message = opensslError("Failed to finalize digest.");
            goto out;
        }
        outputLen = digestLen;
    }

    result.success = true;
    result.primaryText = QByteArray(reinterpret_cast<char *>(output), outputLen).toHex();

out:
    OPENSSL_free(output);
    EVP_MD_CTX_free(context);
    return result;
}

} // namespace Crypto::DigestService
