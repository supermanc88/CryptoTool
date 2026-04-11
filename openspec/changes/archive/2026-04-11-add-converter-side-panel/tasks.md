## 1. Shell Integration

- [x] 1.1 Add a shared, collapsible converter side panel to the main window shell beside the calculator page stack
- [x] 1.2 Define the panel’s open, close, and layout behavior so it preserves usable page space when expanded
- [x] 1.3 Add shared panel state wiring and status feedback without introducing implicit binding to active page fields

## 2. Converter Workspace

- [x] 2.1 Implement shared conversion logic for the initial byte-oriented formats: hex, UTF-8, and Base64
- [x] 2.2 Build the converter workspace UI for manual source entry, source and target format selection, conversion result display, and clear or copy actions
- [x] 2.3 Add validation and user-visible error handling for malformed source content in each supported format

## 3. Explicit Page Interactions

- [x] 3.1 Add explicit send-to-converter actions on representative calculator fields without mutating those fields in place
- [x] 3.2 Ensure calculator operations continue parsing only their own page inputs and are unaffected by converter panel state
- [x] 3.3 Decide and implement whether converted results are copy-only in the first version or can also be inserted back into selected target fields

## 4. Verification and Refinement

- [x] 4.1 Verify the converter panel works consistently across the main calculator pages and remains visually coherent with the shared shell
- [x] 4.2 Validate representative conversion flows, including manual conversion, explicit page send, invalid input handling, and copy behavior
- [x] 4.3 Review panel width, collapse behavior, and interaction density to keep the converter from overpowering the main algorithm workspace
