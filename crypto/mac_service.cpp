#include "crypto/mac_service.h"

#include <openssl/core_names.h>
#include <openssl/evp.h>

namespace Crypto::MacService {

OperationResult calculate(const QString &macMode,
                          const QString &internalMode,
                          const QString &keyHex,
                          const QString &plainHex)
{
    OperationResult result;
    QByteArray keyBytes = QByteArray::fromHex(normalizeHex(keyHex).toUtf8());
    QByteArray plainBytes = QByteArray::fromHex(normalizeHex(plainHex).toUtf8());

    EVP_MAC *mac = nullptr;
    EVP_MAC_CTX *context = nullptr;
    unsigned char *macValue = static_cast<unsigned char *>(OPENSSL_malloc(1024));
    size_t macLen = 1024;
    QByteArray internalModeLatin1 = internalMode.toLatin1();
    OSSL_PARAM params[2] = {OSSL_PARAM_END, OSSL_PARAM_END};

    if (macMode == "HMAC") {
        mac = EVP_MAC_fetch(nullptr, "HMAC", nullptr);
        params[0] = OSSL_PARAM_construct_utf8_string(OSSL_MAC_PARAM_DIGEST, internalModeLatin1.data(), 0);
    } else if (macMode == "CMAC") {
        mac = EVP_MAC_fetch(nullptr, "CMAC", nullptr);
        params[0] = OSSL_PARAM_construct_utf8_string(OSSL_MAC_PARAM_CIPHER, internalModeLatin1.data(), 0);
    } else if (macMode == "GMAC") {
        mac = EVP_MAC_fetch(nullptr, "GMAC", nullptr);
        params[0] = OSSL_PARAM_construct_utf8_string(OSSL_MAC_PARAM_CIPHER, internalModeLatin1.data(), 0);
    } else {
        result.message = "Unsupported MAC mode.";
        goto out;
    }

    context = EVP_MAC_CTX_new(mac);
    if (!mac || !context || !macValue
        || EVP_MAC_init(context,
                        reinterpret_cast<const unsigned char *>(keyBytes.constData()),
                        keyBytes.size(),
                        params) <= 0
        || EVP_MAC_update(context,
                          reinterpret_cast<const unsigned char *>(plainBytes.constData()),
                          plainBytes.size()) <= 0
        || EVP_MAC_final(context, macValue, &macLen, macLen) <= 0) {
        result.message = opensslError("Failed to calculate MAC.");
        goto out;
    }

    result.success = true;
    result.primaryText = QByteArray(reinterpret_cast<char *>(macValue), macLen).toHex();

out:
    OPENSSL_free(macValue);
    EVP_MAC_CTX_free(context);
    EVP_MAC_free(mac);
    return result;
}

QStringList internalModes(const QString &macMode)
{
    if (macMode == "HMAC") {
        return {
            "SHA1", "SHA224", "SHA256", "SHA384", "SHA512", "SHA512-224", "SHA512-256",
            "SHA3-224", "SHA3-256", "SHA3-384", "SHA3-512", "BLAKE2B-512", "BLAKE2S-256",
            "SM3", "SHAKE128", "SHAKE256"
        };
    }
    if (macMode == "CMAC") {
        return {"AES-128-CBC", "AES-192-CBC", "AES-256-CBC", "DES-EDE3-CBC", "DES-CBC", "SM4-CBC"};
    }
    if (macMode == "GMAC") {
        return {"AES-128-GCM", "AES-192-GCM", "AES-256-GCM", "SM4-GCM"};
    }
    return {};
}

} // namespace Crypto::MacService
