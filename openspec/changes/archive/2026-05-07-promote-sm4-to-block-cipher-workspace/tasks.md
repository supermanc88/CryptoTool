## 1. Navigation and Workspace Restructure

- [x] 1.1 Replace the top-level `SM4` navigation entry with a `块加密运算` workspace entry in the main shell
- [x] 1.2 Add a block cipher workspace container page with an explicit in-page algorithm switch for `SM4` and `AES`
- [x] 1.3 Rehost the current SM4 experience inside the new block cipher workspace without changing its core operational flow

## 2. AES Capability

- [x] 2.1 Add an AES crypto service with representative block and AEAD mode support suitable for the workspace
- [x] 2.2 Create an AES page or subview that follows the block cipher workflow model with setup, input, output, and tag areas
- [x] 2.3 Add explicit validation and user-visible error handling for AES-specific invalid key, IV or nonce, input, and mode requirements

## 3. Shared UX and Integration

- [x] 3.1 Keep converter-panel interactions working from the block cipher workspace, including explicit send actions for SM4 and AES outputs
- [x] 3.2 Keep `Stream` as a separate top-level page and ensure no navigation regression moves it under block ciphers
- [x] 3.3 Align naming, hero text, and English helper labels so the workspace consistently reads as `块加密运算` / `Block Cipher Workspace`

## 4. Verification

- [x] 4.1 Verify workspace navigation, algorithm switching, and SM4 continuity after the restructure
- [x] 4.2 Validate representative AES encryption and decryption flows, including at least one AEAD-style path if supported in the first scope
- [x] 4.3 Review the workspace layout density to ensure the parent container plus algorithm switch does not make the page feel heavier than the old SM4 page
