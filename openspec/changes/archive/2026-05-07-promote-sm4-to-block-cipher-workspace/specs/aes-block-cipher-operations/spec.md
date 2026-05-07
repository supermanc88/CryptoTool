## ADDED Requirements

### Requirement: AES is available inside the block cipher workspace
The block cipher workspace SHALL provide AES as a supported algorithm alongside SM4.

#### Scenario: User selects AES
- **WHEN** the user opens `块加密运算` and selects `AES`
- **THEN** the workspace SHALL display an AES-specific operational view
- **AND** that view SHALL be reachable without switching to a different first-level navigation entry

### Requirement: AES supports the block cipher workflow model
The AES view SHALL support the same high-level workflow model as other block cipher views: algorithm setup, encryption or decryption actions, input, output, and any required auxiliary fields for supported modes.

#### Scenario: User prepares an AES operation
- **WHEN** the user is on the AES view
- **THEN** the interface SHALL provide fields for key material, mode selection, input, and output
- **AND** it SHALL provide IV or nonce fields when the selected mode requires them

### Requirement: AES supports representative encryption and decryption modes
The AES view SHALL support representative block cipher and AEAD modes that are sufficient for common calculator usage.

#### Scenario: User runs a standard block mode
- **WHEN** the user selects a supported AES block mode and provides valid inputs
- **THEN** the workspace SHALL allow the user to execute encryption or decryption
- **AND** it SHALL display the resulting output in the AES view

#### Scenario: User runs a supported AEAD mode
- **WHEN** the user selects a supported AES AEAD mode and provides any required AAD or tag-related inputs
- **THEN** the workspace SHALL process the operation using that mode
- **AND** it SHALL display output and any resulting authentication tag fields required by the mode

### Requirement: AES validation is explicit
The AES view SHALL reject invalid or incomplete algorithm material with user-visible errors rather than silently attempting to continue.

#### Scenario: User provides invalid AES material
- **WHEN** the user enters invalid key, IV, nonce, input, or mode-specific parameters for the selected AES workflow
- **THEN** the workspace SHALL prevent a successful operation result
- **AND** it SHALL present a user-visible error describing the invalid input condition
