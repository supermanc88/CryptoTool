## ADDED Requirements

### Requirement: AES key wrap supports standard and padded variants
The AES key wrap workflow SHALL support both standard key wrap and padded key wrap variants.

#### Scenario: User selects a wrap variant
- **WHEN** the user is in the AES key wrap workflow
- **THEN** the page SHALL allow the user to choose between `AES-KW` and `AES-KWP`
- **AND** the selected variant SHALL control which crypto algorithm is used

### Requirement: AES key wrap validates variant-specific input constraints
The AES key wrap workflow SHALL reject invalid or malformed input according to the selected key-wrap variant and operation direction.

#### Scenario: User provides invalid wrap input
- **WHEN** the user provides key material or wrapped data that is invalid for the selected `AES-KW` or `AES-KWP` workflow
- **THEN** the system SHALL prevent a successful result
- **AND** it SHALL present a user-visible validation or processing error

### Requirement: Existing AES block-cipher workflow remains intact
Adding key wrap SHALL not remove or break the existing AES block-cipher workflow.

#### Scenario: User stays on block cipher mode
- **WHEN** the user uses the AES page for ordinary block-cipher work
- **THEN** the existing AES block-cipher controls and operations SHALL remain available
- **AND** key-wrap-specific fields SHALL not interfere with that workflow
