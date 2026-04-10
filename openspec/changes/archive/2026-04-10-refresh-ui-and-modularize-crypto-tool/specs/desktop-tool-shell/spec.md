## ADDED Requirements

### Requirement: Desktop tool shell SHALL provide a structured calculator workspace
The application SHALL provide a desktop shell that organizes the available cryptographic calculators into a consistent navigable workspace rather than relying on a single monolithic fixed-geometry surface.

#### Scenario: User navigates between tool areas
- **WHEN** the user opens the application and selects a different algorithm or tool area
- **THEN** the application SHALL present the selected calculator within the same window shell using a consistent navigation pattern and page structure

### Requirement: Calculator pages SHALL use layout-based composition
Each calculator page SHALL use Qt layout management to arrange controls, labels, actions, and output regions so the interface remains usable across supported window sizes and font settings.

#### Scenario: Window size changes
- **WHEN** the user resizes the main window or runs the application with a different system font scale
- **THEN** the page content SHALL reflow through layouts without relying on manually fixed absolute positions for core usability

### Requirement: Calculator pages SHALL present a consistent visual hierarchy
Each calculator page SHALL present inputs, actions, and results with consistent grouping and labeling so users can quickly identify where to enter data, trigger operations, and inspect outputs.

#### Scenario: User performs a calculation
- **WHEN** the user opens any supported calculator page
- **THEN** the page SHALL expose a clearly identifiable input region, action region, and result region using a consistent visual pattern across tool areas

### Requirement: The shell SHALL preserve current calculator coverage during redesign
The redesigned application shell SHALL continue to expose the existing categories of calculator functionality covered by the current desktop tool.

#### Scenario: Existing tool areas remain available
- **WHEN** the redesigned shell is completed
- **THEN** users SHALL still be able to access SM2, SM3, SM4, RSA, DSA, digest, MAC, stream, and utility calculation workflows from the desktop application
