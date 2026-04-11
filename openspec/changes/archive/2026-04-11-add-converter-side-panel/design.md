## Context

The application now uses a shared main window shell and independent calculator pages under [`widgets/`](/Users/chengheming/Source/QT/CryptoTool/widgets). Those pages currently read directly from field text when an operation runs, so in-place encoding conversion would blur the boundary between what a field displays and what the service layer will parse. The requested change introduces a new cross-page workflow: users want to inspect and transform data representations without silently altering calculator semantics.

The existing architecture is well suited to a shared panel because the main window already coordinates navigation and common shell layout. The design challenge is not conversion logic alone; it is preserving a clear model where algorithm inputs remain explicit while converted data is handled in a separate workspace.

## Goals / Non-Goals

**Goals:**
- Add a shared right-side converter panel that can be shown or hidden across calculator pages.
- Keep conversion behavior explicit by requiring manual source entry or explicit send actions from a page.
- Support a first-class byte representation workflow for common formats such as hex, UTF-8, and Base64.
- Allow users to inspect, copy, and optionally reuse converted data without mutating page fields implicitly.
- Reuse a single conversion experience across all calculator pages instead of embedding ad hoc controls into each field.

**Non-Goals:**
- Do not turn every input or output field into a self-converting smart field.
- Do not infer source data from focused controls or current selection without a user action.
- Do not add semantic crypto-specific decoders such as ASN.1, PEM parsing, or key-structure visualization in this change.
- Do not redesign calculator page layouts beyond what is needed to host the shared panel and explicit send actions.

## Decisions

### 1. Use a shared, collapsible side panel at the main window shell level

The converter will live beside the page stack in the main window shell rather than inside each page. This matches the existing shell architecture and avoids duplicating conversion UI across pages.

Why this over per-page controls:
- A single panel keeps behavior consistent across all tools.
- It avoids crowding already dense calculator pages.
- It reinforces that conversion is a reusable side workflow, not part of the crypto algorithm contract.

Alternative considered:
- Add conversion controls next to each text field. Rejected because it would create repetitive UI, increase implementation noise, and encourage field-local behavior that is easy to misunderstand.

### 2. Keep data flow explicit: manual entry first, page-to-panel send as an explicit action

The panel SHALL never read from the currently focused field automatically. Users will either type or paste source content into the panel, or trigger an explicit page action such as “Send to Converter.”

Why this over implicit focus tracking:
- It preserves a predictable mental model.
- It removes hidden coupling between current focus and conversion behavior.
- It prevents accidental conversion of the wrong data when users navigate quickly between fields.

Alternative considered:
- Automatically bind the converter to the active text edit. Rejected because it is opaque and error-prone in a multi-page, multi-field crypto tool.

### 3. Treat the converter as a representation workspace, not a field mutator

The converter will operate on its own source text, source format, target format, and result surface. The primary actions are convert, copy, clear, and optional insert-back into a chosen target field.

Why this over in-place mutation:
- Calculator fields today are also parse inputs for services.
- In-place conversion risks changing the meaning of a future operation click.
- A separate workspace preserves original page semantics and makes conversion reversible by design.

Alternative considered:
- Convert field contents in place while tracking a hidden field format state. Rejected for initial scope because it complicates page state, increases the chance of mismatch bugs, and makes state less visible.

### 4. Scope the first version to byte-oriented formats

The first implementation should support common representations used across the app: hex, UTF-8, and Base64. Other formats can be added later if demand is real.

Why this narrower scope:
- These formats cover the majority of payload conversion needs in current pages.
- They map cleanly to the app’s existing byte-oriented crypto workflows.
- They keep validation and user messaging understandable.

Alternative considered:
- Build a generic “all encodings” converter. Rejected because it would broaden scope quickly and blur the product into a general-purpose data lab.

## Risks / Trade-offs

- [Panel complexity grows into a secondary app] → Keep the first version focused on representation conversion, copy, and explicit send or insert behavior only.
- [Users assume panel content mirrors the current page] → Make the panel visually independent, label its source clearly, and avoid any automatic binding.
- [Insert-back targets become confusing] → Start with copy-first behavior and add target insertion only where page context is explicit and the destination list is small.
- [Unsupported or invalid conversions create noisy failures] → Add strict validation and direct error messages for malformed hex, invalid Base64, and non-decodable UTF-8 cases.
- [Right-side panel reduces main workspace width] → Make the panel collapsible and keep its default width constrained.

## Migration Plan

1. Add the shared converter panel to the main window shell with collapsed and expanded states.
2. Implement shared conversion logic and panel-local validation rules.
3. Connect representative pages to explicit “Send to Converter” actions where it improves flow.
4. Add copy actions and, if included in final scope, controlled insert-back actions for selected page fields.
5. Verify that algorithm operations still parse only their own field contents and are unaffected by side-panel conversions.

Rollback is straightforward because the panel is additive at the shell level. If issues emerge, the panel can be disabled without changing crypto service interfaces.

## Open Questions

- Should converter state persist while switching pages, or reset when the user navigates?
- Should “insert back” be part of the first delivery, or should the first version stop at conversion plus copy?
- Which pages most benefit from explicit “Send to Converter” actions in the initial rollout: all pages, or only those with high-frequency payload outputs?
