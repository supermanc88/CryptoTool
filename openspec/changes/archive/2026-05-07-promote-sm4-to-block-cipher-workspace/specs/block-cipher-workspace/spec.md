## ADDED Requirements

### Requirement: Block cipher workspace entry
The application SHALL expose a first-level navigation entry named `块加密运算` as the primary entry point for block cipher workflows instead of exposing `SM4` as a standalone first-level page.

#### Scenario: User opens the navigation
- **WHEN** the main window navigation is rendered
- **THEN** the navigation SHALL include `块加密运算`
- **AND** it SHALL not expose the old first-level `SM4` label as a separate peer entry

### Requirement: Workspace hosts multiple block cipher algorithms
The block cipher workspace SHALL allow the user to switch between supported block cipher algorithms within the same workspace entry.

#### Scenario: User changes algorithm inside the workspace
- **WHEN** the user opens `块加密运算`
- **THEN** the page SHALL present an explicit algorithm switch for the supported block cipher algorithms
- **AND** changing that selection SHALL switch the active block cipher view without requiring the user to leave the workspace

### Requirement: SM4 remains available inside the workspace
The current SM4 workflow SHALL remain available as one algorithm inside the block cipher workspace.

#### Scenario: User selects SM4
- **WHEN** the user selects `SM4` inside `块加密运算`
- **THEN** the page SHALL present an SM4 workflow with configuration, input, output, and tag areas
- **AND** the user SHALL still be able to run SM4 encryption and decryption from that view

### Requirement: Stream page remains separate
The application SHALL keep stream-cipher workflows outside the block cipher workspace.

#### Scenario: User wants stream ciphers
- **WHEN** the user looks for RC4 or ChaCha20 operations
- **THEN** those workflows SHALL remain under the separate `Stream` page
- **AND** they SHALL not be moved under `块加密运算` in this change
