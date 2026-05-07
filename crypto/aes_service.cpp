#include "crypto/aes_service.h"

#include <QRegularExpression>

#include <openssl/evp.h>

namespace {

Crypto::OperationResult invalidField(const QString &message)
{
    Crypto::OperationResult result;
    result.message = message;
    return result;
}

Crypto::OperationResult parseHexField(const QString &text,
                                      const QString &fieldName,
                                      bool required,
                                      QByteArray *out)
{
    const QString normalized = Crypto::normalizeHex(text);
    if (normalized.isEmpty()) {
        if (required) {
            return invalidField(fieldName + " is required.");
        }
        *out = QByteArray();
        return {};
    }

    static const QRegularExpression hexPattern("^[0-9a-fA-F]+$");
    if (!hexPattern.match(normalized).hasMatch() || (normalized.size() % 2) != 0) {
        return invalidField(fieldName + " must be valid hex.");
    }

    *out = QByteArray::fromHex(normalized.toUtf8());
    return {};
}

const EVP_CIPHER *resolveAesCipher(int keySize, const QString &mode)
{
    if (mode == "ECB") {
        if (keySize == 16) {
            return EVP_aes_128_ecb();
        }
        if (keySize == 24) {
            return EVP_aes_192_ecb();
        }
        if (keySize == 32) {
            return EVP_aes_256_ecb();
        }
    } else if (mode == "CBC") {
        if (keySize == 16) {
            return EVP_aes_128_cbc();
        }
        if (keySize == 24) {
            return EVP_aes_192_cbc();
        }
        if (keySize == 32) {
            return EVP_aes_256_cbc();
        }
    } else if (mode == "CTR") {
        if (keySize == 16) {
            return EVP_aes_128_ctr();
        }
        if (keySize == 24) {
            return EVP_aes_192_ctr();
        }
        if (keySize == 32) {
            return EVP_aes_256_ctr();
        }
    } else if (mode == "GCM") {
        if (keySize == 16) {
            return EVP_aes_128_gcm();
        }
        if (keySize == 24) {
            return EVP_aes_192_gcm();
        }
        if (keySize == 32) {
            return EVP_aes_256_gcm();
        }
    }

    return nullptr;
}

} // namespace

namespace Crypto::AesService {

OperationResult process(const QString &keyHex,
                        const QString &inputHex,
                        const QString &ivHex,
                        const QString &aadHex,
                        const QString &tagHex,
                        const QString &mode,
                        const QString &padding,
                        bool encryptMode)
{
    OperationResult result;

    QByteArray keyBytes;
    QByteArray inputBytes;
    QByteArray ivBytes;
    QByteArray aadBytes;
    QByteArray tagBytes;

    auto fieldResult = parseHexField(keyHex, "Key", true, &keyBytes);
    if (!fieldResult.message.isEmpty()) {
        return fieldResult;
    }
    fieldResult = parseHexField(inputHex, "Input", true, &inputBytes);
    if (!fieldResult.message.isEmpty()) {
        return fieldResult;
    }

    const bool needsIv = mode != "ECB";
    fieldResult = parseHexField(ivHex, "IV / nonce", needsIv, &ivBytes);
    if (!fieldResult.message.isEmpty()) {
        return fieldResult;
    }
    fieldResult = parseHexField(aadHex, "AAD", false, &aadBytes);
    if (!fieldResult.message.isEmpty()) {
        return fieldResult;
    }
    fieldResult = parseHexField(tagHex, "Tag", mode == "GCM" && !encryptMode, &tagBytes);
    if (!fieldResult.message.isEmpty()) {
        return fieldResult;
    }

    if (keyBytes.size() != 16 && keyBytes.size() != 24 && keyBytes.size() != 32) {
        return invalidField("AES key must be 128, 192, or 256 bits.");
    }

    const EVP_CIPHER *cipher = resolveAesCipher(keyBytes.size(), mode);
    if (!cipher) {
        return invalidField("Unsupported AES mode.");
    }

    if ((mode == "CBC" || mode == "CTR") && ivBytes.size() != 16) {
        return invalidField("IV / nonce must be 16 bytes for the selected AES mode.");
    }

    if (mode == "GCM") {
        if (ivBytes.isEmpty()) {
            return invalidField("IV / nonce is required for AES-GCM.");
        }
        if (tagBytes.size() > 0 && tagBytes.size() != 16) {
            return invalidField("AES-GCM tag must be 16 bytes.");
        }
    }

    EVP_CIPHER_CTX *context = EVP_CIPHER_CTX_new();
    if (!context) {
        result.message = opensslError("Failed to create AES context.");
        return result;
    }

    const int blockSize = EVP_CIPHER_block_size(cipher);
    unsigned char *output = static_cast<unsigned char *>(OPENSSL_malloc(inputBytes.size() + blockSize + 32));
    int outputLen = 0;
    int tmpLen = 0;
    unsigned char generatedTag[16] = {0};

    if (!output) {
        result.message = "Failed to allocate AES buffer.";
        EVP_CIPHER_CTX_free(context);
        return result;
    }

    if (mode == "GCM") {
        if (EVP_CipherInit_ex(context, cipher, nullptr, nullptr, nullptr, encryptMode ? 1 : 0) != 1) {
            result.message = opensslError("Failed to initialize AES-GCM.");
            goto out;
        }
        if (EVP_CIPHER_CTX_ctrl(context, EVP_CTRL_GCM_SET_IVLEN, ivBytes.size(), nullptr) != 1) {
            result.message = opensslError("Failed to set AES-GCM IV length.");
            goto out;
        }
        if (!encryptMode
            && EVP_CIPHER_CTX_ctrl(context, EVP_CTRL_GCM_SET_TAG, tagBytes.size(), tagBytes.data()) != 1) {
            result.message = opensslError("Failed to set AES-GCM tag.");
            goto out;
        }
        if (EVP_CipherInit_ex(context,
                              nullptr,
                              nullptr,
                              reinterpret_cast<const unsigned char *>(keyBytes.constData()),
                              reinterpret_cast<const unsigned char *>(ivBytes.constData()),
                              encryptMode ? 1 : 0) != 1) {
            result.message = opensslError("Failed to set AES-GCM key and IV.");
            goto out;
        }
        if (!aadBytes.isEmpty()
            && EVP_CipherUpdate(context,
                                nullptr,
                                &tmpLen,
                                reinterpret_cast<const unsigned char *>(aadBytes.constData()),
                                aadBytes.size()) != 1) {
            result.message = opensslError("Failed to process AES-GCM AAD.");
            goto out;
        }
    } else {
        if (EVP_CipherInit_ex(context,
                              cipher,
                              nullptr,
                              reinterpret_cast<const unsigned char *>(keyBytes.constData()),
                              ivBytes.isEmpty() ? nullptr : reinterpret_cast<const unsigned char *>(ivBytes.constData()),
                              encryptMode ? 1 : 0) != 1) {
            result.message = opensslError("Failed to initialize AES cipher.");
            goto out;
        }
        EVP_CIPHER_CTX_set_padding(context, padding == "是" ? 1 : 0);
    }

    if (EVP_CipherUpdate(context,
                         output,
                         &tmpLen,
                         reinterpret_cast<const unsigned char *>(inputBytes.constData()),
                         inputBytes.size()) != 1) {
        result.message = opensslError("Failed to process AES input.");
        goto out;
    }
    outputLen = tmpLen;

    if (EVP_CipherFinal_ex(context, output + outputLen, &tmpLen) != 1) {
        result.message = opensslError("Failed to finalize AES operation.");
        goto out;
    }
    outputLen += tmpLen;

    result.success = true;
    result.primaryText = QByteArray(reinterpret_cast<char *>(output), outputLen).toHex();

    if (mode == "GCM" && encryptMode) {
        if (EVP_CIPHER_CTX_ctrl(context, EVP_CTRL_GCM_GET_TAG, 16, generatedTag) != 1) {
            result.success = false;
            result.message = opensslError("Failed to fetch AES-GCM tag.");
            goto out;
        }
        result.secondaryText = QByteArray(reinterpret_cast<char *>(generatedTag), sizeof(generatedTag)).toHex();
    }

out:
    OPENSSL_free(output);
    EVP_CIPHER_CTX_free(context);
    return result;
}

} // namespace Crypto::AesService
