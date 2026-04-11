#ifndef SHARED_CONVERTER_SERVICE_H
#define SHARED_CONVERTER_SERVICE_H

#include "shared/crypto_common.h"

namespace ConverterService {

QStringList supportedFormats();
Crypto::ConversionResult decode(const QString &text, const QString &format);
Crypto::ConversionResult convert(const QString &text, const QString &sourceFormat, const QString &targetFormat);

} // namespace ConverterService

#endif // SHARED_CONVERTER_SERVICE_H
