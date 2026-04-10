## Why

The current application still behaves like a single-window prototype: the UI is built with fixed absolute positioning, and nearly all interaction and OpenSSL logic lives inside `MainWindow`. This makes the tool harder to use, harder to extend, and harder to maintain as more cryptographic calculators are added.

This change is needed now because the project already spans multiple algorithm domains and tabs, but the visual structure and code organization have not kept pace with that growth. Improving the desktop experience and introducing clear module boundaries will make the tool more usable for algorithm calculations and will reduce the cost of future changes.

## What Changes

- Redesign the desktop UI around reusable page structure, responsive layouts, and a cleaner visual hierarchy suited to a multi-tool cryptography calculator.
- Replace the current absolute-position-heavy widget arrangement with layout-based composition that behaves correctly across window sizes and font settings.
- Reorganize the application so `MainWindow` acts as a container and coordinator rather than the home for most cryptographic operations.
- Split algorithm-specific logic into focused modules or services grouped by capability domains such as SM2, SM3, SM4, RSA, DSA, digest, MAC, and stream tools.
- Introduce shared utility layers for common concerns such as hex/text conversion, OpenSSL helper routines, and operation result/error handling.
- Preserve the existing algorithm calculator scope while improving discoverability, readability, and maintainability.

## Capabilities

### New Capabilities
- `desktop-tool-shell`: A structured desktop application shell with consistent navigation, page composition, and visual presentation for the existing crypto calculators.
- `crypto-operation-modules`: A modular application structure that separates UI coordination from algorithm-specific cryptographic operations and shared helpers.

### Modified Capabilities

None.

## Impact

- Affected code: [`mainwindow.cpp`](/Users/chengheming/Source/QT/CryptoTool/mainwindow.cpp), [`mainwindow.h`](/Users/chengheming/Source/QT/CryptoTool/mainwindow.h), [`mainwindow.ui`](/Users/chengheming/Source/QT/CryptoTool/mainwindow.ui), [`main.cpp`](/Users/chengheming/Source/QT/CryptoTool/main.cpp), [`CryptoTool.pro`](/Users/chengheming/Source/QT/CryptoTool/CryptoTool.pro)
- New code areas are expected for page widgets, crypto service/modules, and shared helpers.
- No new external runtime dependency is required beyond the existing Qt Widgets and OpenSSL setup.
- The user-visible desktop workflow and the internal code structure will both change, but the project remains a local cryptographic calculation tool rather than a service or API.
