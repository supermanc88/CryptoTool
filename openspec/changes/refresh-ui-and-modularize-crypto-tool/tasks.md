## 1. Application Shell Redesign

- [x] 1.1 Define the new main window shell structure and replace fixed-geometry top-level composition with layout-based containers
- [x] 1.2 Implement consistent navigation and page hosting for the existing calculator domains
- [x] 1.3 Create a reusable page composition pattern for title, input area, action area, and result area
- [x] 1.4 Apply a unified visual style for spacing, grouping, control sizing, and result presentation across calculator pages

## 2. Page Migration

- [x] 2.1 Migrate the SM2 page to the new shell and page composition as the representative high-complexity calculator
- [x] 2.2 Migrate the SM3, SM4, RSA, and DSA pages to the new page composition pattern
- [x] 2.3 Migrate the digest, MAC, stream, and utility tool pages to the new page composition pattern
- [x] 2.4 Verify that all current calculator categories remain reachable and usable from the redesigned shell

## 3. Crypto Module Extraction

- [x] 3.1 Define domain-oriented module boundaries for SM2, SM3, SM4, RSA, DSA, digest, MAC, stream, and shared utilities
- [x] 3.2 Extract shared helper behavior for parsing, hex or text conversion, OpenSSL support, and result or error formatting
- [x] 3.3 Move SM2 logic out of `MainWindow` into dedicated modules and update the UI layer to delegate to them
- [x] 3.4 Move the remaining calculator operation logic out of `MainWindow` into their corresponding domain modules

## 4. Integration and Cleanup

- [x] 4.1 Reduce `MainWindow` to shell coordination, navigation, and UI event wiring responsibilities
- [x] 4.2 Update project files and includes to reflect the new page and module structure
- [ ] 4.3 Validate that representative workflows still behave correctly after modularization and UI migration
- [x] 4.4 Remove obsolete monolithic UI and implementation remnants that are no longer used by the redesigned structure
