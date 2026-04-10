#include "crypto/stream_service.h"

#include <openssl/evp.h>

namespace Crypto::StreamService {

OperationResult process(const QString &mode,
                        const QString &keyHex,
                        const QString &inputHex,
                        const QString &ivHex,
                        bool encryptMode)
{
    OperationResult result;
    QByteArray keyBytes = QByteArray::fromHex(normalizeHex(keyHex).toUtf8());
    QByteArray inputBytes = QByteArray::fromHex(normalizeHex(inputHex).toUtf8());
    QByteArray ivBytes = QByteArray::fromHex(normalizeHex(ivHex).toUtf8());

    const EVP_CIPHER *cipher = nullptr;
    if (mode == "rc4") {
        cipher = EVP_rc4();
    } else if (mode == "chacha20") {
        cipher = EVP_chacha20();
    } else {
        result.message = "Unsupported stream mode.";
        return result;
    }

    EVP_CIPHER_CTX *context = EVP_CIPHER_CTX_new();
    unsigned char *output = static_cast<unsigned char *>(OPENSSL_malloc(inputBytes.size() + EVP_CIPHER_block_size(cipher) + 16));
    int len = 0;
    int total = 0;

    if (!context || !output
        || EVP_CipherInit_ex(context,
                             cipher,
                             nullptr,
                             reinterpret_cast<const unsigned char *>(keyBytes.constData()),
                             ivBytes.isEmpty() ? nullptr : reinterpret_cast<const unsigned char *>(ivBytes.constData()),
                             encryptMode ? 1 : 0) != 1
        || EVP_CipherUpdate(context,
                            output,
                            &len,
                            reinterpret_cast<const unsigned char *>(inputBytes.constData()),
                            inputBytes.size()) != 1) {
        result.message = opensslError("Failed to initialize stream cipher.");
        goto out;
    }

    total = len;
    if (EVP_CipherFinal_ex(context, output + total, &len) != 1) {
        result.message = opensslError("Failed to finalize stream cipher.");
        goto out;
    }
    total += len;

    result.success = true;
    result.primaryText = QByteArray(reinterpret_cast<char *>(output), total).toHex();

out:
    OPENSSL_free(output);
    EVP_CIPHER_CTX_free(context);
    return result;
}

} // namespace Crypto::StreamService
