## Why

The application now has cleaner calculator pages, but data representation work still happens outside the product or by manually overwriting field contents. That makes common tasks like viewing output as UTF-8 or preparing input in another encoding clumsy and increases the risk of breaking later calculations by mutating algorithm fields in place.

## What Changes

- Add a shared, collapsible converter side panel that is available across calculator pages.
- Support manual source input plus explicit conversion between common byte-oriented formats such as hex, UTF-8, and Base64.
- Allow users to copy converted output and optionally send page values into the converter through explicit actions rather than implicit focus tracking.
- Preserve calculator field semantics so encoding conversion does not silently change what operation buttons will parse.

## Capabilities

### New Capabilities
- `converter-side-panel`: A shared right-side panel that can be shown or hidden, reused across pages, and used as the application’s common data conversion workspace.
- `manual-conversion-workflow`: An explicit conversion flow where users provide or send source text, choose source and target formats, inspect conversion results, and avoid hidden coupling to algorithm fields.

### Modified Capabilities

## Impact

- Affected code: [`mainwindow.cpp`](/Users/chengheming/Source/QT/CryptoTool/mainwindow.cpp), shared page shell layout, and reusable widget infrastructure under [`widgets/`](/Users/chengheming/Source/QT/CryptoTool/widgets).
- New UI behavior: global collapsible side panel, page-to-converter explicit send actions, and conversion result actions such as copy or paste-back.
- New shared logic: format parsing, conversion validation, and presentation rules for supported encodings.
