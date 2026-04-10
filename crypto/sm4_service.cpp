#include "crypto/sm4_service.h"

#include <openssl/evp.h>

namespace Crypto::Sm4Service {

OperationResult process(const QString &keyHex,
                        const QString &inputHex,
                        const QString &ivHex,
                        const QString &aadHex,
                        const QString &mode,
                        const QString &padding,
                        bool encryptMode)
{
    OperationResult result;
    QByteArray keyBytes = QByteArray::fromHex(normalizeHex(keyHex).toUtf8());
    QByteArray inputBytes = QByteArray::fromHex(normalizeHex(inputHex).toUtf8());
    QByteArray ivBytes = QByteArray::fromHex(normalizeHex(ivHex).toUtf8());
    QByteArray aadBytes = QByteArray::fromHex(normalizeHex(aadHex).toUtf8());

    EVP_CIPHER_CTX *context = EVP_CIPHER_CTX_new();
    EVP_CIPHER *dynamicCipher = nullptr;
    unsigned char *output = nullptr;
    int outputLen = 0;
    int tmpLen = 0;
    unsigned char tag[16] = {0};

    if (!context) {
        result.message = opensslError("Failed to create SM4 context.");
        return result;
    }

    output = static_cast<unsigned char *>(OPENSSL_malloc(inputBytes.size() + 64));
    if (!output) {
        result.message = "Failed to allocate SM4 buffer.";
        goto out;
    }

    if (mode == "ECB") {
        if (EVP_CipherInit(context, EVP_sm4_ecb(),
                           reinterpret_cast<const unsigned char *>(keyBytes.constData()),
                           nullptr,
                           encryptMode ? 1 : 0) != 1) {
            result.message = opensslError("Failed to initialize SM4 ECB.");
            goto out;
        }
    } else if (mode == "CBC") {
        if (EVP_CipherInit(context, EVP_sm4_cbc(),
                           reinterpret_cast<const unsigned char *>(keyBytes.constData()),
                           reinterpret_cast<const unsigned char *>(ivBytes.constData()),
                           encryptMode ? 1 : 0) != 1) {
            result.message = opensslError("Failed to initialize SM4 CBC.");
            goto out;
        }
    } else if (mode == "CFB") {
        if (EVP_CipherInit(context, EVP_sm4_cfb(),
                           reinterpret_cast<const unsigned char *>(keyBytes.constData()),
                           reinterpret_cast<const unsigned char *>(ivBytes.constData()),
                           encryptMode ? 1 : 0) != 1) {
            result.message = opensslError("Failed to initialize SM4 CFB.");
            goto out;
        }
    } else if (mode == "OFB") {
        if (EVP_CipherInit(context, EVP_sm4_ofb(),
                           reinterpret_cast<const unsigned char *>(keyBytes.constData()),
                           reinterpret_cast<const unsigned char *>(ivBytes.constData()),
                           encryptMode ? 1 : 0) != 1) {
            result.message = opensslError("Failed to initialize SM4 OFB.");
            goto out;
        }
    } else if (mode == "CTR") {
        if (EVP_CipherInit(context, EVP_sm4_ctr(),
                           reinterpret_cast<const unsigned char *>(keyBytes.constData()),
                           reinterpret_cast<const unsigned char *>(ivBytes.constData()),
                           encryptMode ? 1 : 0) != 1) {
            result.message = opensslError("Failed to initialize SM4 CTR.");
            goto out;
        }
    } else if (mode == "GCM" || mode == "CCM" || mode == "XTS") {
        const QString cipherName = "SM4-" + mode;
        dynamicCipher = EVP_CIPHER_fetch(nullptr, cipherName.toLatin1().constData(), nullptr);
        if (!dynamicCipher) {
            result.message = opensslError("Failed to fetch SM4 cipher.");
            goto out;
        }
        if (EVP_CipherInit(context, dynamicCipher, nullptr, nullptr, encryptMode ? 1 : 0) != 1) {
            result.message = opensslError("Failed to initialize SM4 AEAD/XTS mode.");
            goto out;
        }
        if (mode == "CCM") {
            if (EVP_CIPHER_CTX_ctrl(context, EVP_CTRL_CCM_SET_IVLEN, 12, nullptr) != 1
                || EVP_CIPHER_CTX_ctrl(context, EVP_CTRL_CCM_SET_TAG, 16, nullptr) != 1) {
                result.message = opensslError("Failed to configure SM4 CCM.");
                goto out;
            }
        }
        if (EVP_CipherInit(context, nullptr,
                           reinterpret_cast<const unsigned char *>(keyBytes.constData()),
                           reinterpret_cast<const unsigned char *>(ivBytes.constData()),
                           encryptMode ? 1 : 0) != 1) {
            result.message = opensslError("Failed to set SM4 key and IV.");
            goto out;
        }
        if (mode == "CCM") {
            if (EVP_CipherUpdate(context, nullptr, &tmpLen, nullptr, inputBytes.size()) != 1) {
                result.message = opensslError("Failed to set SM4 CCM message length.");
                goto out;
            }
        }
        if ((mode == "GCM" || mode == "CCM")
            && !aadBytes.isEmpty()
            && EVP_CipherUpdate(context, nullptr, &tmpLen,
                                reinterpret_cast<const unsigned char *>(aadBytes.constData()),
                                aadBytes.size()) != 1) {
            result.message = opensslError("Failed to set SM4 AAD.");
            goto out;
        }
    } else {
        result.message = "Unsupported SM4 mode.";
        goto out;
    }

    EVP_CIPHER_CTX_set_padding(context, padding == "是" ? 1 : 0);

    if (EVP_CipherUpdate(context,
                         output,
                         &tmpLen,
                         reinterpret_cast<const unsigned char *>(inputBytes.constData()),
                         inputBytes.size()) != 1) {
        result.message = opensslError("Failed to process SM4 input.");
        goto out;
    }
    outputLen = tmpLen;

    if (EVP_CipherFinal(context,
                        output + outputLen,
                        &tmpLen) != 1) {
        result.message = opensslError("Failed to finalize SM4 operation.");
        goto out;
    }
    outputLen += tmpLen;

    result.success = true;
    result.primaryText = QByteArray(reinterpret_cast<char *>(output), outputLen).toHex();

    if (mode == "GCM" && EVP_CIPHER_CTX_ctrl(context, EVP_CTRL_GCM_GET_TAG, 16, tag) == 1) {
        result.secondaryText = QByteArray(reinterpret_cast<char *>(tag), sizeof(tag)).toHex();
    }
    if (mode == "CCM" && EVP_CIPHER_CTX_ctrl(context, EVP_CTRL_CCM_GET_TAG, 16, tag) == 1) {
        result.secondaryText = QByteArray(reinterpret_cast<char *>(tag), sizeof(tag)).toHex();
    }

out:
    EVP_CIPHER_CTX_free(context);
    EVP_CIPHER_free(dynamicCipher);
    OPENSSL_free(output);
    return result;
}

} // namespace Crypto::Sm4Service
