#include "crypto/sm2_service.h"

#include <openssl/ec.h>
#include <openssl/evp.h>

namespace {

int computeZDigest(uint8_t *out,
                   const EVP_MD *digest,
                   const uint8_t *id,
                   size_t idLen,
                   const EC_KEY *key)
{
    const EC_GROUP *group = EC_KEY_get0_group(key);
    BN_CTX *ctx = BN_CTX_new();
    EVP_MD_CTX *hash = EVP_MD_CTX_new();
    if (!ctx || !hash || !group) {
        BN_CTX_free(ctx);
        EVP_MD_CTX_free(hash);
        return 0;
    }

    BIGNUM *p = BN_CTX_get(ctx);
    BIGNUM *a = BN_CTX_get(ctx);
    BIGNUM *b = BN_CTX_get(ctx);
    BIGNUM *xG = BN_CTX_get(ctx);
    BIGNUM *yG = BN_CTX_get(ctx);
    BIGNUM *xA = BN_CTX_get(ctx);
    BIGNUM *yA = BN_CTX_get(ctx);
    if (!yA) {
        BN_CTX_free(ctx);
        EVP_MD_CTX_free(hash);
        return 0;
    }

    if (!EVP_DigestInit(hash, digest)) {
        BN_CTX_free(ctx);
        EVP_MD_CTX_free(hash);
        return 0;
    }

    uint16_t entl = static_cast<uint16_t>(idLen * 8);
    uint8_t head[2] = {
        static_cast<uint8_t>(entl >> 8),
        static_cast<uint8_t>(entl & 0xFF)
    };

    if (!EVP_DigestUpdate(hash, head, sizeof(head))
        || (idLen > 0 && !EVP_DigestUpdate(hash, id, idLen))
        || !EC_GROUP_get_curve(group, p, a, b, ctx)) {
        BN_CTX_free(ctx);
        EVP_MD_CTX_free(hash);
        return 0;
    }

    int fieldBytes = BN_num_bytes(p);
    uint8_t *buffer = static_cast<uint8_t *>(OPENSSL_zalloc(fieldBytes));
    if (!buffer) {
        BN_CTX_free(ctx);
        EVP_MD_CTX_free(hash);
        return 0;
    }

    bool ok =
        BN_bn2binpad(a, buffer, fieldBytes) >= 0
        && EVP_DigestUpdate(hash, buffer, fieldBytes)
        && BN_bn2binpad(b, buffer, fieldBytes) >= 0
        && EVP_DigestUpdate(hash, buffer, fieldBytes)
        && EC_POINT_get_affine_coordinates(group, EC_GROUP_get0_generator(group), xG, yG, ctx)
        && BN_bn2binpad(xG, buffer, fieldBytes) >= 0
        && EVP_DigestUpdate(hash, buffer, fieldBytes)
        && BN_bn2binpad(yG, buffer, fieldBytes) >= 0
        && EVP_DigestUpdate(hash, buffer, fieldBytes)
        && EC_POINT_get_affine_coordinates(group, EC_KEY_get0_public_key(key), xA, yA, ctx)
        && BN_bn2binpad(xA, buffer, fieldBytes) >= 0
        && EVP_DigestUpdate(hash, buffer, fieldBytes)
        && BN_bn2binpad(yA, buffer, fieldBytes) >= 0
        && EVP_DigestUpdate(hash, buffer, fieldBytes)
        && EVP_DigestFinal(hash, out, nullptr);

    OPENSSL_free(buffer);
    BN_CTX_free(ctx);
    EVP_MD_CTX_free(hash);
    return ok ? 1 : 0;
}

} // namespace

namespace Crypto::Sm2Service {

KeyPairResult generateKeyPair()
{
    KeyPairResult result;
    EVP_PKEY_CTX *context = EVP_PKEY_CTX_new_id(EVP_PKEY_EC, nullptr);
    EVP_PKEY *pkey = nullptr;

    if (!context
        || EVP_PKEY_keygen_init(context) <= 0
        || EVP_PKEY_CTX_set_ec_paramgen_curve_nid(context, NID_sm2) <= 0
        || EVP_PKEY_keygen(context, &pkey) <= 0) {
        result.message = opensslError("Failed to generate SM2 key pair.");
        EVP_PKEY_CTX_free(context);
        EVP_PKEY_free(pkey);
        return result;
    }

    EC_KEY *ecKey = const_cast<EC_KEY *>(EVP_PKEY_get0_EC_KEY(pkey));
    const BIGNUM *privateKey = EC_KEY_get0_private_key(ecKey);
    const EC_POINT *publicKey = EC_KEY_get0_public_key(ecKey);

    result.privateKey = bnToHex(privateKey);
    char *publicKeyHex = EC_POINT_point2hex(EC_KEY_get0_group(ecKey), publicKey, POINT_CONVERSION_UNCOMPRESSED, nullptr);
    result.publicKey = publicKeyHex ? QString::fromLatin1(publicKeyHex) : QString();
    if (publicKeyHex) {
        OPENSSL_free(publicKeyHex);
    }
    result.success = !result.privateKey.isEmpty() && !result.publicKey.isEmpty();
    if (!result.success) {
        result.message = "Failed to extract SM2 key material.";
    }

    EVP_PKEY_CTX_free(context);
    EVP_PKEY_free(pkey);
    return result;
}

OperationResult signHash(const QString &privateKeyHex, const QString &hashHex)
{
    OperationResult result;
    QByteArray privateKeyBytes = QByteArray::fromHex(normalizeHex(privateKeyHex).toUtf8());
    QByteArray hashBytes = QByteArray::fromHex(normalizeHex(hashHex).toUtf8());

    BIGNUM *privateKey = BN_bin2bn(reinterpret_cast<const unsigned char *>(privateKeyBytes.constData()), privateKeyBytes.size(), nullptr);
    EC_KEY *ecKey = EC_KEY_new_by_curve_name(NID_sm2);
    EVP_PKEY *pkey = EVP_PKEY_new();
    EVP_PKEY_CTX *context = nullptr;
    unsigned char *signature = nullptr;
    size_t signatureLen = 72;

    if (!privateKey || !ecKey || !pkey
        || EC_KEY_set_private_key(ecKey, privateKey) != 1
        || EVP_PKEY_set1_EC_KEY(pkey, ecKey) != 1
        || !(context = EVP_PKEY_CTX_new(pkey, nullptr))
        || EVP_PKEY_sign_init(context) <= 0) {
        result.message = opensslError("Failed to initialize SM2 signing.");
        goto out;
    }

    signature = static_cast<unsigned char *>(OPENSSL_malloc(signatureLen));
    if (!signature || EVP_PKEY_sign(context, signature, &signatureLen,
                                    reinterpret_cast<const unsigned char *>(hashBytes.constData()),
                                    hashBytes.size()) <= 0) {
        result.message = opensslError("Failed to sign SM2 hash.");
        goto out;
    }

    result.success = true;
    result.primaryText = QByteArray(reinterpret_cast<char *>(signature), signatureLen).toHex();

out:
    BN_free(privateKey);
    EC_KEY_free(ecKey);
    EVP_PKEY_free(pkey);
    EVP_PKEY_CTX_free(context);
    OPENSSL_free(signature);
    return result;
}

OperationResult verifySignature(const QString &publicKeyHex, const QString &hashHex, const QString &signatureHex)
{
    OperationResult result;
    QByteArray publicKeyBytes = QByteArray::fromHex(normalizeHex(publicKeyHex).toUtf8());
    QByteArray hashBytes = QByteArray::fromHex(normalizeHex(hashHex).toUtf8());
    QByteArray signatureBytes = QByteArray::fromHex(normalizeHex(signatureHex).toUtf8());

    EC_KEY *ecKey = EC_KEY_new_by_curve_name(NID_sm2);
    EVP_PKEY *pkey = EVP_PKEY_new();
    EVP_PKEY_CTX *context = nullptr;

    if (!ecKey || !pkey
        || EC_KEY_oct2key(ecKey,
                          reinterpret_cast<const unsigned char *>(publicKeyBytes.constData()),
                          publicKeyBytes.size(),
                          nullptr) != 1
        || EVP_PKEY_set1_EC_KEY(pkey, ecKey) != 1
        || !(context = EVP_PKEY_CTX_new(pkey, nullptr))
        || EVP_PKEY_verify_init(context) <= 0) {
        result.message = opensslError("Failed to initialize SM2 verification.");
        goto out;
    }

    if (EVP_PKEY_verify(context,
                        reinterpret_cast<const unsigned char *>(signatureBytes.constData()),
                        signatureBytes.size(),
                        reinterpret_cast<const unsigned char *>(hashBytes.constData()),
                        hashBytes.size()) != 1) {
        result.message = "Failed to verify signature.";
        result.primaryText = result.message;
        goto out;
    }

    result.success = true;
    result.primaryText = "Signature verified.";

out:
    EC_KEY_free(ecKey);
    EVP_PKEY_free(pkey);
    EVP_PKEY_CTX_free(context);
    return result;
}

OperationResult encrypt(const QString &publicKeyHex, const QString &plainHex)
{
    OperationResult result;
    QByteArray publicKeyBytes = QByteArray::fromHex(normalizeHex(publicKeyHex).toUtf8());
    QByteArray plainBytes = QByteArray::fromHex(normalizeHex(plainHex).toUtf8());

    EC_KEY *ecKey = EC_KEY_new_by_curve_name(NID_sm2);
    EVP_PKEY *pkey = EVP_PKEY_new();
    EVP_PKEY_CTX *context = nullptr;
    unsigned char *cipherText = nullptr;
    size_t cipherTextLen = plainBytes.size() + 128;

    if (!ecKey || !pkey
        || EC_KEY_oct2key(ecKey,
                          reinterpret_cast<const unsigned char *>(publicKeyBytes.constData()),
                          publicKeyBytes.size(),
                          nullptr) != 1
        || EVP_PKEY_set1_EC_KEY(pkey, ecKey) != 1
        || !(context = EVP_PKEY_CTX_new(pkey, nullptr))
        || EVP_PKEY_encrypt_init(context) <= 0) {
        result.message = opensslError("Failed to initialize SM2 encryption.");
        goto out;
    }

    cipherText = static_cast<unsigned char *>(OPENSSL_malloc(cipherTextLen));
    if (!cipherText
        || EVP_PKEY_encrypt(context,
                            cipherText,
                            &cipherTextLen,
                            reinterpret_cast<const unsigned char *>(plainBytes.constData()),
                            plainBytes.size()) <= 0) {
        result.message = opensslError("Failed to encrypt SM2 plaintext.");
        goto out;
    }

    result.success = true;
    result.primaryText = QByteArray(reinterpret_cast<char *>(cipherText), cipherTextLen).toHex();

out:
    EC_KEY_free(ecKey);
    EVP_PKEY_free(pkey);
    EVP_PKEY_CTX_free(context);
    OPENSSL_free(cipherText);
    return result;
}

OperationResult decrypt(const QString &privateKeyHex, const QString &cipherHex)
{
    OperationResult result;
    QByteArray privateKeyBytes = QByteArray::fromHex(normalizeHex(privateKeyHex).toUtf8());
    QByteArray cipherBytes = QByteArray::fromHex(normalizeHex(cipherHex).toUtf8());

    BIGNUM *privateKey = BN_bin2bn(reinterpret_cast<const unsigned char *>(privateKeyBytes.constData()), privateKeyBytes.size(), nullptr);
    EC_KEY *ecKey = EC_KEY_new_by_curve_name(NID_sm2);
    EVP_PKEY *pkey = EVP_PKEY_new();
    EVP_PKEY_CTX *context = nullptr;
    unsigned char *plainText = nullptr;
    size_t plainTextLen = cipherBytes.size();

    if (!privateKey || !ecKey || !pkey
        || EC_KEY_set_private_key(ecKey, privateKey) != 1
        || EVP_PKEY_set1_EC_KEY(pkey, ecKey) != 1
        || !(context = EVP_PKEY_CTX_new(pkey, nullptr))
        || EVP_PKEY_decrypt_init(context) <= 0) {
        result.message = opensslError("Failed to initialize SM2 decryption.");
        goto out;
    }

    plainText = static_cast<unsigned char *>(OPENSSL_malloc(plainTextLen));
    if (!plainText
        || EVP_PKEY_decrypt(context,
                            plainText,
                            &plainTextLen,
                            reinterpret_cast<const unsigned char *>(cipherBytes.constData()),
                            cipherBytes.size()) <= 0) {
        result.message = opensslError("Failed to decrypt SM2 ciphertext.");
        goto out;
    }

    result.success = true;
    result.primaryText = QByteArray(reinterpret_cast<char *>(plainText), plainTextLen).toHex();

out:
    BN_free(privateKey);
    EC_KEY_free(ecKey);
    EVP_PKEY_free(pkey);
    EVP_PKEY_CTX_free(context);
    OPENSSL_free(plainText);
    return result;
}

OperationResult derivePublicKey(const QString &privateKeyHex)
{
    OperationResult result;
    QByteArray privateKeyBytes = QByteArray::fromHex(normalizeHex(privateKeyHex).toUtf8());
    EC_KEY *ecKey = EC_KEY_new_by_curve_name(NID_sm2);
    BIGNUM *privateKey = nullptr;
    EC_POINT *publicKey = nullptr;

    if (!ecKey) {
        result.message = opensslError("Failed to create SM2 key.");
        return result;
    }

    const EC_GROUP *group = EC_KEY_get0_group(ecKey);
    privateKey = BN_bin2bn(reinterpret_cast<const unsigned char *>(privateKeyBytes.constData()), privateKeyBytes.size(), nullptr);
    publicKey = EC_POINT_new(group);

    if (!privateKey || !publicKey
        || EC_KEY_set_private_key(ecKey, privateKey) != 1
        || EC_POINT_mul(group, publicKey, privateKey, nullptr, nullptr, nullptr) != 1
        || EC_KEY_set_public_key(ecKey, publicKey) != 1) {
        result.message = opensslError("Failed to derive SM2 public key.");
        goto out;
    }

    {
        char *publicKeyHex = EC_POINT_point2hex(group, publicKey, POINT_CONVERSION_UNCOMPRESSED, nullptr);
        result.primaryText = publicKeyHex ? QString::fromLatin1(publicKeyHex) : QString();
        if (publicKeyHex) {
            OPENSSL_free(publicKeyHex);
        }
    }
    result.success = !result.primaryText.isEmpty();
    if (!result.success) {
        result.message = "Failed to derive SM2 public key.";
    }

out:
    EC_KEY_free(ecKey);
    BN_free(privateKey);
    EC_POINT_free(publicKey);
    return result;
}

OperationResult hashWithZa(const QString &publicKeyHex,
                           const QString &userId,
                           const QString &userIdInputType,
                           const QString &plainText,
                           const QString &plainInputType)
{
    OperationResult result;
    QByteArray publicKeyBytes = QByteArray::fromHex(normalizeHex(publicKeyHex).toUtf8());
    if (publicKeyBytes.size() == 64) {
        publicKeyBytes.prepend(char(0x04));
    }

    QByteArray userIdBytes = parseInput(userId, userIdInputType);
    QByteArray plainBytes = parseInput(plainText, plainInputType);

    EC_KEY *ecKey = EC_KEY_new_by_curve_name(NID_sm2);
    EVP_MD_CTX *hash = EVP_MD_CTX_new();
    const EVP_MD *digest = EVP_sm3();
    const int digestSize = EVP_MD_size(digest);
    uint8_t *za = static_cast<uint8_t *>(OPENSSL_malloc(digestSize));

    if (!ecKey || !hash || !za
        || EC_KEY_oct2key(ecKey,
                          reinterpret_cast<const unsigned char *>(publicKeyBytes.constData()),
                          publicKeyBytes.size(),
                          nullptr) != 1
        || !computeZDigest(za,
                           digest,
                           reinterpret_cast<const uint8_t *>(userIdBytes.constData()),
                           static_cast<size_t>(userIdBytes.size()),
                           ecKey)
        || !EVP_DigestInit(hash, digest)
        || !EVP_DigestUpdate(hash, za, digestSize)
        || !EVP_DigestUpdate(hash, plainBytes.constData(), plainBytes.size())
        || !EVP_DigestFinal(hash, za, nullptr)) {
        result.message = opensslError("Failed to calculate SM3 ZA hash.");
        EC_KEY_free(ecKey);
        EVP_MD_CTX_free(hash);
        OPENSSL_free(za);
        return result;
    }

    result.success = true;
    result.primaryText = QByteArray(reinterpret_cast<char *>(za), digestSize).toHex();

    EC_KEY_free(ecKey);
    EVP_MD_CTX_free(hash);
    OPENSSL_free(za);
    return result;
}

} // namespace Crypto::Sm2Service
