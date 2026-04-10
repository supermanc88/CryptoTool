#include "crypto/dsa_service.h"

#include <openssl/dsa.h>

namespace {

DSA *createDsaKey(const QString &publicKeyHex,
                  const QString &privateKeyHex,
                  const QString &pHex,
                  const QString &qHex,
                  const QString &gHex,
                  bool includePrivate)
{
    const QByteArray publicKeyBytes = QByteArray::fromHex(Crypto::normalizeHex(publicKeyHex).toUtf8());
    const QByteArray privateKeyBytes = QByteArray::fromHex(Crypto::normalizeHex(privateKeyHex).toUtf8());
    const QByteArray pBytes = QByteArray::fromHex(Crypto::normalizeHex(pHex).toUtf8());
    const QByteArray qBytes = QByteArray::fromHex(Crypto::normalizeHex(qHex).toUtf8());
    const QByteArray gBytes = QByteArray::fromHex(Crypto::normalizeHex(gHex).toUtf8());

    BIGNUM *publicKey = BN_bin2bn(reinterpret_cast<const unsigned char *>(publicKeyBytes.constData()),
                                  publicKeyBytes.size(),
                                  nullptr);
    BIGNUM *privateKey = includePrivate
        ? BN_bin2bn(reinterpret_cast<const unsigned char *>(privateKeyBytes.constData()),
                    privateKeyBytes.size(),
                    nullptr)
        : nullptr;
    BIGNUM *p = BN_bin2bn(reinterpret_cast<const unsigned char *>(pBytes.constData()),
                          pBytes.size(),
                          nullptr);
    BIGNUM *q = BN_bin2bn(reinterpret_cast<const unsigned char *>(qBytes.constData()),
                          qBytes.size(),
                          nullptr);
    BIGNUM *g = BN_bin2bn(reinterpret_cast<const unsigned char *>(gBytes.constData()),
                          gBytes.size(),
                          nullptr);

    DSA *dsa = DSA_new();
    if (!dsa
        || !p || !q || !g
        || DSA_set0_pqg(dsa, p, q, g) != 1
        || DSA_set0_key(dsa, publicKey, privateKey) != 1) {
        DSA_free(dsa);
        BN_free(publicKey);
        BN_free(privateKey);
        BN_free(p);
        BN_free(q);
        BN_free(g);
        return nullptr;
    }

    return dsa;
}

} // namespace

namespace Crypto::DsaService {

DsaKeyPairResult generateKeyPair()
{
    DsaKeyPairResult result;
    EVP_PKEY *params = nullptr;
    EVP_PKEY *pkey = nullptr;
    EVP_PKEY_CTX *paramContext = EVP_PKEY_CTX_new_id(EVP_PKEY_DSA, nullptr);
    EVP_PKEY_CTX *keyContext = nullptr;

    if (!paramContext
        || EVP_PKEY_paramgen_init(paramContext) <= 0
        || EVP_PKEY_CTX_set_dsa_paramgen_bits(paramContext, 2048) <= 0
        || EVP_PKEY_paramgen(paramContext, &params) <= 0) {
        result.message = opensslError("Failed to generate DSA parameters.");
        goto out;
    }

    keyContext = EVP_PKEY_CTX_new(params, nullptr);
    if (!keyContext
        || EVP_PKEY_keygen_init(keyContext) <= 0
        || EVP_PKEY_keygen(keyContext, &pkey) <= 0) {
        result.message = opensslError("Failed to generate DSA key pair.");
        goto out;
    }

    {
        DSA *dsa = EVP_PKEY_get1_DSA(pkey);
        const BIGNUM *publicKey = nullptr;
        const BIGNUM *privateKey = nullptr;
        const BIGNUM *p = nullptr;
        const BIGNUM *q = nullptr;
        const BIGNUM *g = nullptr;
        DSA_get0_key(dsa, &publicKey, &privateKey);
        DSA_get0_pqg(dsa, &p, &q, &g);
        result.publicKey = bnToHex(publicKey);
        result.privateKey = bnToHex(privateKey);
        result.p = bnToHex(p);
        result.q = bnToHex(q);
        result.g = bnToHex(g);
        result.success = !result.publicKey.isEmpty() && !result.privateKey.isEmpty();
        if (!result.success) {
            result.message = "Failed to extract DSA key material.";
        }
        DSA_free(dsa);
    }

out:
    EVP_PKEY_free(params);
    EVP_PKEY_free(pkey);
    EVP_PKEY_CTX_free(paramContext);
    EVP_PKEY_CTX_free(keyContext);
    return result;
}

OperationResult sign(const QString &publicKeyHex,
                     const QString &privateKeyHex,
                     const QString &dataHex,
                     const QString &pHex,
                     const QString &qHex,
                     const QString &gHex,
                     const QString &digestName)
{
    OperationResult result;
    const EVP_MD *digest = resolveDigest(digestName);
    if (!digest) {
        result.message = "Unsupported DSA digest mode.";
        return result;
    }

    QByteArray dataBytes = QByteArray::fromHex(normalizeHex(dataHex).toUtf8());
    DSA *dsa = createDsaKey(publicKeyHex, privateKeyHex, pHex, qHex, gHex, true);
    EVP_PKEY *pkey = EVP_PKEY_new();
    EVP_MD_CTX *context = EVP_MD_CTX_new();
    unsigned char *signature = nullptr;
    size_t signatureLen = 1024;

    if (!dsa || !pkey || !context
        || EVP_PKEY_set1_DSA(pkey, dsa) != 1
        || EVP_DigestSignInit(context, nullptr, digest, nullptr, pkey) <= 0
        || EVP_DigestSignUpdate(context,
                                reinterpret_cast<const unsigned char *>(dataBytes.constData()),
                                dataBytes.size()) <= 0) {
        result.message = opensslError("Failed to initialize DSA signing.");
        goto out;
    }

    signature = static_cast<unsigned char *>(OPENSSL_malloc(signatureLen));
    if (!signature || EVP_DigestSignFinal(context, signature, &signatureLen) <= 0) {
        result.message = opensslError("Failed to sign DSA data.");
        goto out;
    }

    result.success = true;
    result.primaryText = QByteArray(reinterpret_cast<char *>(signature), signatureLen).toHex();

out:
    OPENSSL_free(signature);
    EVP_MD_CTX_free(context);
    EVP_PKEY_free(pkey);
    DSA_free(dsa);
    return result;
}

OperationResult verify(const QString &publicKeyHex,
                       const QString &dataHex,
                       const QString &signatureHex,
                       const QString &pHex,
                       const QString &qHex,
                       const QString &gHex,
                       const QString &digestName)
{
    OperationResult result;
    const EVP_MD *digest = resolveDigest(digestName);
    if (!digest) {
        result.message = "Unsupported DSA digest mode.";
        return result;
    }

    QByteArray dataBytes = QByteArray::fromHex(normalizeHex(dataHex).toUtf8());
    QByteArray signatureBytes = QByteArray::fromHex(normalizeHex(signatureHex).toUtf8());
    DSA *dsa = createDsaKey(publicKeyHex, {}, pHex, qHex, gHex, false);
    EVP_PKEY *pkey = EVP_PKEY_new();
    EVP_MD_CTX *context = EVP_MD_CTX_new();

    if (!dsa || !pkey || !context
        || EVP_PKEY_set1_DSA(pkey, dsa) != 1
        || EVP_DigestVerifyInit(context, nullptr, digest, nullptr, pkey) <= 0
        || EVP_DigestVerifyUpdate(context,
                                  reinterpret_cast<const unsigned char *>(dataBytes.constData()),
                                  dataBytes.size()) <= 0) {
        result.message = opensslError("Failed to initialize DSA verification.");
        goto out;
    }

    if (EVP_DigestVerifyFinal(context,
                              reinterpret_cast<const unsigned char *>(signatureBytes.constData()),
                              signatureBytes.size()) != 1) {
        result.primaryText = "Verify Failed.";
        result.message = result.primaryText;
        goto out;
    }

    result.success = true;
    result.primaryText = "Verify Success.";

out:
    EVP_MD_CTX_free(context);
    EVP_PKEY_free(pkey);
    DSA_free(dsa);
    return result;
}

} // namespace Crypto::DsaService
