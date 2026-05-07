## Why

The application currently exposes `SM4` as a first-level navigation item, which mixes a specific block cipher with broader capability-oriented entries such as `MAC`, `digest`, and `Stream`. Adding `AES` is a good point to correct that information architecture and turn the existing `SM4` page into a clearer block-cipher entry point.

## What Changes

- Replace the first-level `SM4` navigation entry with a `块加密运算` workspace entry.
- Reframe the current `SM4` experience as one algorithm inside that workspace rather than a standalone top-level tool.
- Add `AES` block cipher support inside the same workspace with explicit algorithm switching.
- Reuse the existing block-cipher workflow shape where possible: key, IV or nonce, AAD, mode, padding, input, output, and tag.
- Preserve the current `Stream` page as a separate workspace rather than merging all symmetric cryptography into one place.

## Capabilities

### New Capabilities
- `block-cipher-workspace`: A shared workspace entry that hosts block cipher algorithms such as SM4 and AES under one navigation item.
- `aes-block-cipher-operations`: AES encryption and decryption support inside the block cipher workspace, including representative block and AEAD modes.

### Modified Capabilities

## Impact

- Affected code: [`mainwindow.cpp`](/Users/chengheming/Source/QT/CryptoTool/mainwindow.cpp), [`mainwindow.h`](/Users/chengheming/Source/QT/CryptoTool/mainwindow.h), [`widgets/sm4page.cpp`](/Users/chengheming/Source/QT/CryptoTool/widgets/sm4page.cpp), [`widgets/sm4page.h`](/Users/chengheming/Source/QT/CryptoTool/widgets/sm4page.h), and new workspace or AES-related files under [`widgets/`](/Users/chengheming/Source/QT/CryptoTool/widgets) and [`crypto/`](/Users/chengheming/Source/QT/CryptoTool/crypto).
- New UI behavior: first-level `块加密运算` navigation plus in-workspace algorithm switching between `SM4` and `AES`.
- New shared logic: AES cipher service implementation and any reusable block-cipher workspace composition needed to host multiple algorithms cleanly.
