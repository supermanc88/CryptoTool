#include "shared/converter_service.h"

#include "shared/crypto_common.h"

#include <QByteArray>
#include <QRegularExpression>
#include <QTextCodec>

namespace {

Crypto::ConversionResult encodeBytes(const QByteArray &bytes, const QString &format)
{
    Crypto::ConversionResult result;
    result.success = true;
    result.bytes = bytes;

    if (format == "Hex") {
        result.text = QString::fromLatin1(bytes.toHex());
        return result;
    }

    if (format == "Base64") {
        result.text = QString::fromLatin1(bytes.toBase64());
        return result;
    }

    QTextCodec *codec = QTextCodec::codecForName("UTF-8");
    QTextCodec::ConverterState state;
    result.text = codec->toUnicode(bytes.constData(), bytes.size(), &state);
    if (state.invalidChars > 0) {
        result.success = false;
        result.message = "Bytes cannot be decoded as valid UTF-8.";
    }
    return result;
}

} // namespace

namespace ConverterService {

QStringList supportedFormats()
{
    return {"Hex", "UTF-8", "Base64"};
}

Crypto::ConversionResult decode(const QString &text, const QString &format)
{
    Crypto::ConversionResult result;
    QByteArray bytes;

    if (format == "UTF-8") {
        bytes = text.toUtf8();
    } else if (format == "Hex") {
        const QString normalized = Crypto::normalizeHex(text);
        static const QRegularExpression hexPattern("^[0-9a-fA-F]*$");
        if (normalized.size() % 2 != 0 || !hexPattern.match(normalized).hasMatch()) {
            result.message = "Invalid hex input.";
            return result;
        }
        bytes = QByteArray::fromHex(normalized.toUtf8());
    } else if (format == "Base64") {
        const QString normalized = text.simplified().remove(' ');
        static const QRegularExpression base64Pattern("^[A-Za-z0-9+/]*={0,2}$");
        if (normalized.isEmpty() || normalized.size() % 4 != 0 || !base64Pattern.match(normalized).hasMatch()) {
            result.message = "Invalid Base64 input.";
            return result;
        }
        bytes = QByteArray::fromBase64(normalized.toLatin1());
        if (QString::fromLatin1(bytes.toBase64()) != normalized) {
            result.message = "Invalid Base64 input.";
            return result;
        }
    } else {
        result.message = "Unsupported source format.";
        return result;
    }

    result.success = true;
    result.bytes = bytes;
    result.text = text;
    return result;
}

Crypto::ConversionResult convert(const QString &text, const QString &sourceFormat, const QString &targetFormat)
{
    const Crypto::ConversionResult decoded = decode(text, sourceFormat);
    if (!decoded.success) {
        return decoded;
    }
    return encodeBytes(decoded.bytes, targetFormat);
}

} // namespace ConverterService
