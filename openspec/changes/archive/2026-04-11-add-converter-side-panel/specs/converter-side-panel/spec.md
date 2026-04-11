## ADDED Requirements

### Requirement: Shared converter side panel
The system SHALL provide a shared converter side panel in the main application shell that is available across calculator pages and can be expanded or collapsed without leaving the current page.

#### Scenario: Open converter panel from a calculator page
- **WHEN** the user is viewing any calculator page and opens the converter panel
- **THEN** the application SHALL show the converter workspace beside the current page without navigating away from that page

#### Scenario: Collapse converter panel
- **WHEN** the user closes or collapses the converter panel
- **THEN** the application SHALL hide the panel and preserve the main calculator page as the active workspace

### Requirement: Converter panel remains distinct from calculator fields
The system SHALL treat the converter panel as a separate workspace whose source text and converted result are not implicitly bound to calculator fields.

#### Scenario: Converter panel opened with no explicit source
- **WHEN** the user opens the converter panel without manually entering text or sending page content into it
- **THEN** the application SHALL present an empty or previously retained converter workspace rather than reading from a page field automatically

#### Scenario: Calculator field edits do not silently update converter contents
- **WHEN** the converter panel is open and the user edits a calculator field
- **THEN** the application SHALL NOT change the converter source or result unless the user performs an explicit send action

### Requirement: Explicit send-to-converter workflow
The system SHALL support page-level actions that explicitly send field content into the shared converter panel.

#### Scenario: Send page output to converter
- **WHEN** the user triggers a send-to-converter action on a page field
- **THEN** the application SHALL populate the converter source with that field’s current content and keep the conversion workflow inside the side panel

#### Scenario: Send action does not rewrite source field
- **WHEN** the user sends a field value into the converter panel
- **THEN** the application SHALL leave the source page field unchanged
