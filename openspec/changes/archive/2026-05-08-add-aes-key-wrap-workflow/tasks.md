## 1. AES Page Workflow Split

- [x] 1.1 Add an AES operation-type switch that separates `Block Cipher` from `Key Wrap`
- [x] 1.2 Keep the current AES block-cipher layout intact behind the `Block Cipher` path
- [x] 1.3 Add a dedicated key-wrap layout with explicit `KEK`, input material, wrapped output, and `Wrap / Unwrap` actions

## 2. AES Key Wrap Service Logic

- [x] 2.1 Add a distinct AES key-wrap processing path instead of overloading the current block-cipher process function
- [x] 2.2 Support both `AES-KW` and `AES-KWP`
- [x] 2.3 Add validation and user-visible errors for invalid KEK sizes, malformed wrapped input, and variant-specific constraints

## 3. Integration and Verification

- [x] 3.1 Keep converter interactions explicit for key-wrap outputs in the AES page
- [x] 3.2 Verify that existing AES block-cipher behavior still works after the workflow split
- [x] 3.3 Validate representative `Wrap / Unwrap` flows for both `AES-KW` and `AES-KWP`
