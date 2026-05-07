## Why

The new `块加密运算` entry improved navigation, but the current implementation still wraps `SM4` and `AES` as page-level children inside a workspace container. That extra page layer creates nested scrolling and makes algorithm switching feel heavier than a single block-cipher workbench.

## What Changes

- Refactor `块加密运算` into a true single-page workspace with one unified scrolling surface.
- Remove page-level child switching for `SM4` and `AES`, and instead switch the algorithm-specific content region in place.
- Keep `SM4` and `AES` under the same workspace entry, but make the user feel like they stay on one page while changing algorithms.
- Preserve existing block-cipher operations, converter actions, and algorithm-specific validation while changing the workspace composition model.

## Capabilities

### New Capabilities
- `single-scroll-block-cipher-workspace`: A block cipher workspace that owns the only page-level scroll context for `SM4` and `AES`.
- `in-place-block-cipher-layout-switching`: An in-page algorithm switching model where `SM4` and `AES` replace the content layout region without routing through nested child pages.

### Modified Capabilities

## Impact

- Affected code: [`widgets/blockcipherworkspacepage.cpp`](/Users/chengheming/Source/QT/CryptoTool/widgets/blockcipherworkspacepage.cpp), [`widgets/blockcipherworkspacepage.h`](/Users/chengheming/Source/QT/CryptoTool/widgets/blockcipherworkspacepage.h), [`widgets/sm4page.cpp`](/Users/chengheming/Source/QT/CryptoTool/widgets/sm4page.cpp), [`widgets/sm4page.h`](/Users/chengheming/Source/QT/CryptoTool/widgets/sm4page.h), [`widgets/aespage.cpp`](/Users/chengheming/Source/QT/CryptoTool/widgets/aespage.cpp), and [`widgets/aespage.h`](/Users/chengheming/Source/QT/CryptoTool/widgets/aespage.h).
- New UI behavior: one `块加密运算` page with one scroll surface and in-place algorithm layout changes.
- Structural impact: `SM4` and `AES` will no longer behave as full nested pages under the workspace container.
