## ADDED Requirements

### Requirement: Algorithm switching is in-place
The block cipher workspace SHALL switch `SM4` and `AES` in place rather than treating them as nested child pages.

#### Scenario: User selects SM4 or AES
- **WHEN** the user clicks the `SM4` or `AES` algorithm switch inside `块加密运算`
- **THEN** the workspace SHALL replace the algorithm-specific layout region in place
- **AND** the interaction SHALL not behave like navigating to a different embedded page

### Requirement: Algorithm-specific controls remain available after flattening
Flattening the workspace SHALL not remove algorithm-specific operational controls needed by `SM4` or `AES`.

#### Scenario: User needs SM4 or AES controls
- **WHEN** the relevant algorithm is active inside `块加密运算`
- **THEN** the workspace SHALL present that algorithm’s required setup, input, output, and tag-related controls
- **AND** the user SHALL still be able to perform the same class of block-cipher operations as before the layout flattening

### Requirement: Converter actions remain explicit in the flattened workspace
The flattened block cipher workspace SHALL preserve explicit converter actions for algorithm outputs without implicitly binding to focused fields.

#### Scenario: User sends algorithm output to the converter
- **WHEN** the user triggers a send-to-converter action from the active `SM4` or `AES` layout
- **THEN** the workspace SHALL send the selected output explicitly to the converter panel
- **AND** the action SHALL not depend on hidden focus-based data binding
