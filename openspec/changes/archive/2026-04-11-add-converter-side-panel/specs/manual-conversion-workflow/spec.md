## ADDED Requirements

### Requirement: Manual source conversion workflow
The system SHALL allow users to manually enter or paste source text into the converter workspace, choose a source format, choose a target format, and generate a converted result.

#### Scenario: Convert manually entered text
- **WHEN** the user enters source text, selects a source format, selects a target format, and runs conversion
- **THEN** the application SHALL display the converted result in the converter result surface

#### Scenario: Clear converter workspace
- **WHEN** the user clears the converter workspace
- **THEN** the application SHALL remove both the current source text and the current converted result from the converter panel

### Requirement: Supported byte-oriented format conversion
The system SHALL support conversion among the byte-oriented formats defined for the feature, including hex, UTF-8, and Base64 in the initial version.

#### Scenario: Convert hex to UTF-8
- **WHEN** the user provides valid hex source data and selects UTF-8 as the target format
- **THEN** the application SHALL decode the hex bytes and display their UTF-8 representation

#### Scenario: Convert UTF-8 to Base64
- **WHEN** the user provides UTF-8 source text and selects Base64 as the target format
- **THEN** the application SHALL encode the resulting bytes as Base64 and display that text

### Requirement: Invalid conversion feedback
The system SHALL reject invalid source content for the selected source format and present a clear error without mutating calculator page fields.

#### Scenario: Invalid hex source
- **WHEN** the user attempts conversion with malformed hex while the source format is hex
- **THEN** the application SHALL show a conversion error and SHALL NOT produce a converted result

#### Scenario: Invalid Base64 source
- **WHEN** the user attempts conversion with malformed Base64 while the source format is Base64
- **THEN** the application SHALL show a conversion error and SHALL NOT produce a converted result

### Requirement: Safe reuse of converted output
The system SHALL support copying converted output for reuse and SHALL keep conversion actions separate from calculator execution semantics.

#### Scenario: Copy converted result
- **WHEN** the user chooses to copy the converted result
- **THEN** the application SHALL place the current converted text onto the clipboard without changing calculator fields

#### Scenario: Conversion does not change operation parsing
- **WHEN** the user performs conversions in the converter panel and then runs a calculator operation
- **THEN** the calculator SHALL continue to parse only its own field contents rather than converter panel state
