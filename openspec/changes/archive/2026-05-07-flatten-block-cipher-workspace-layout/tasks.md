## 1. Workspace Flattening

- [x] 1.1 Refactor `BlockCipherWorkspacePage` so it owns the only page-level scroll shell for `块加密运算`
- [x] 1.2 Remove page-level child switching for `SM4` and `AES` and replace it with one in-place algorithm content host
- [x] 1.3 Keep the workspace hero, naming, and algorithm switch stable while changing only the active content region

## 2. Algorithm Content Refactor

- [x] 2.1 Refactor the current `SM4` UI into an embeddable content region that no longer owns its own page-level scrolling shell
- [x] 2.2 Refactor the current `AES` UI into an embeddable content region that no longer owns its own page-level scrolling shell
- [x] 2.3 Preserve status reporting, converter actions, and algorithm-specific validation after flattening the composition

## 3. Verification

- [x] 3.1 Verify that `块加密运算` now uses one stable scroll surface for both `SM4` and `AES`
- [x] 3.2 Verify that algorithm switching feels in-place rather than like changing nested subpages
- [x] 3.3 Check that `SM4` and `AES` still expose their required controls and operations after the refactor
