## ADDED Requirements

### Requirement: Block cipher workspace uses one page-level scroll context
The `块加密运算` workspace SHALL own the only page-level scrolling surface used while working with `SM4` and `AES`.

#### Scenario: User scrolls inside the block cipher workspace
- **WHEN** the user is viewing `块加密运算`
- **THEN** scrolling SHALL be handled by a single workspace-level scrolling surface
- **AND** the workspace SHALL not require nested page-level scroll areas for `SM4` and `AES`

### Requirement: Workspace framing remains stable across algorithm switches
The workspace SHALL preserve one stable page shell while changing the active algorithm content.

#### Scenario: User switches algorithm
- **WHEN** the user changes from `SM4` to `AES` or from `AES` to `SM4`
- **THEN** the surrounding `块加密运算` workspace frame SHALL remain the same page
- **AND** only the algorithm-specific content region SHALL change
