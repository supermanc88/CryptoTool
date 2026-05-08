## Why

The current AES page only models ordinary block-cipher and AEAD workflows, so adding key wrap as just another mode would blur field semantics and make the page harder to understand. AES key wrap is a distinct operation type with different inputs and outputs, and the AES workspace is now the right place to expose it explicitly.

## What Changes

- Add an explicit `Key Wrap` operation type inside the AES page alongside the existing block-cipher workflow.
- Support both `AES-KW` and `AES-KWP` variants in the AES key wrap flow.
- Support both `Wrap` and `Unwrap` actions with fields that are named for key-encryption-key and wrapped key material semantics.
- Keep the existing AES block-cipher workflow intact rather than overloading its `mode / IV / AAD / tag` model with key wrap concerns.

## Capabilities

### New Capabilities
- `aes-key-wrap-workflow`: A dedicated AES page workflow for wrapping and unwrapping key material using AES key wrap semantics.
- `aes-wrap-variant-support`: Variant support for `AES-KW` and `AES-KWP`, including the operational differences between standard wrap and padded wrap.

### Modified Capabilities

## Impact

- Affected code: [`widgets/aespage.cpp`](/Users/chengheming/Source/QT/CryptoTool/widgets/aespage.cpp), [`widgets/aespage.h`](/Users/chengheming/Source/QT/CryptoTool/widgets/aespage.h), and new or expanded AES service logic under [`crypto/aes_service.cpp`](/Users/chengheming/Source/QT/CryptoTool/crypto/aes_service.cpp) and [`crypto/aes_service.h`](/Users/chengheming/Source/QT/CryptoTool/crypto/aes_service.h).
- New UI behavior: the AES page gains an operation-type switch between ordinary block-cipher work and key wrap work.
- New crypto behavior: explicit AES key wrap and unwrap support for both standard and padded variants.
