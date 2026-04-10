## ADDED Requirements

### Requirement: Main window SHALL not own most cryptographic execution logic
The main window SHALL coordinate navigation, page display, and UI event flow, while algorithm-specific cryptographic execution SHALL reside in focused modules or services outside the main window implementation.

#### Scenario: User triggers an operation
- **WHEN** the user clicks a calculator action such as key generation, signing, verification, encryption, decryption, digest calculation, or MAC calculation
- **THEN** the UI layer SHALL delegate the algorithm execution to a capability-specific module or service instead of embedding the full operation flow inside `MainWindow`

### Requirement: Algorithm modules SHALL be organized by capability domain
The codebase SHALL group cryptographic execution logic by capability domains that align with the tool surface, such as SM2, SM3, SM4, RSA, DSA, digest, MAC, stream, and shared utility operations.

#### Scenario: Developer locates algorithm logic
- **WHEN** a developer needs to modify or inspect the implementation for a specific calculator domain
- **THEN** the relevant operation code SHALL be located in files or modules dedicated to that domain rather than mixed across unrelated UI handlers

### Requirement: Shared helper concerns SHALL be extracted from individual tool handlers
The codebase SHALL provide shared helper facilities for repeated concerns such as input normalization, text or hex conversion, OpenSSL helper routines, and result or error formatting when those concerns are used by multiple calculator domains.

#### Scenario: Multiple calculators use the same helper behavior
- **WHEN** more than one calculator domain requires the same parsing, formatting, or common OpenSSL support behavior
- **THEN** that behavior SHALL be implemented in a shared helper layer instead of being duplicated across multiple UI event handlers

### Requirement: Refactoring SHALL preserve feature behavior while improving maintainability
The modularization effort SHALL preserve the current user-visible calculator capabilities while reducing the concentration of code in single window-level implementation files.

#### Scenario: Existing workflow continues after modularization
- **WHEN** a user performs an already supported calculator workflow after the refactor
- **THEN** the workflow SHALL remain available with equivalent functional intent while the underlying implementation is routed through the new module boundaries
