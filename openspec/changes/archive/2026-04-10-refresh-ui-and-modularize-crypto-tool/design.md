## Context

The current project is a Qt Widgets desktop application that exposes multiple cryptographic calculators in a single `QMainWindow`. The current UI is defined in a large `.ui` file that uses fixed geometry for nearly every control, and the implementation places most event handling and OpenSSL operations directly inside `MainWindow`.

This creates two immediate constraints:

- The UI is visually dense and inflexible because it lacks layout-based composition and consistent spacing rules.
- The code is hard to evolve because UI wiring, input parsing, cryptographic execution, and result formatting are tightly coupled in one class.

The application is not being repositioned as a service, API, or multi-user product. It remains a local desktop tool for running algorithm calculations. The design therefore needs to improve visual quality and maintainability without introducing unnecessary platform or framework churn.

## Goals / Non-Goals

**Goals:**

- Create a more polished desktop interface for algorithm calculation workflows.
- Replace absolute-positioned widget composition with reusable layout-based page structure.
- Reduce `MainWindow` responsibilities so that algorithm execution lives in domain-oriented modules or services.
- Preserve the existing set of crypto tool areas while making them easier to navigate and extend.
- Introduce shared patterns for result presentation, validation feedback, and common helper behavior.

**Non-Goals:**

- Rewriting the application in QML or changing the project away from Qt Widgets.
- Expanding the application scope with remote APIs, persistence, accounts, or cloud features.
- Redesigning every cryptographic algorithm implementation from scratch.
- Changing the tool into a tutorial workflow with step-by-step algorithm education as the primary purpose.

## Decisions

### Decision: Keep Qt Widgets and modernize the shell inside the existing stack

The application SHALL remain a Qt Widgets app and improve presentation through layout composition, reusable widget structure, and application-wide styling.

Rationale:

- The current project already uses `QMainWindow`, `.ui`, and widget-based interaction.
- The required improvement is architectural and visual, not a framework migration.
- Staying on Qt Widgets reduces risk and keeps the change focused on usability and maintainability.

Alternatives considered:

- Move to QML: rejected because it would increase scope and introduce a second major migration at the same time as structural refactoring.
- Leave the UI structure intact and only add stylesheets: rejected because fixed geometry would still limit the result and keep the UI brittle.

### Decision: Convert the application shell to a navigation-plus-page layout

The main window SHALL act as an application shell that exposes grouped tool navigation and hosts focused tool pages, rather than presenting all behavior through a monolithic tab surface with ad hoc geometry.

Rationale:

- The tool already spans multiple algorithm domains and benefits from clearer grouping.
- A stable shell makes it easier to standardize page title, input section, action section, and result section patterns.
- It supports future growth without requiring the entire UI file to remain a single giant surface.

Alternatives considered:

- Keep the existing large tab widget and only tweak spacing: rejected because it preserves the current scaling and maintenance problems.
- Create one independent top-level window per algorithm: rejected because it fragments the user workflow for a calculation tool that benefits from a unified workspace.

### Decision: Introduce page-level UI components with service-level crypto modules

Each major algorithm/tool area SHALL be represented by a focused page widget or page section, while cryptographic execution SHALL move into domain-oriented modules or services outside `MainWindow`.

Target structure:

```text
MainWindow
├─ application shell
├─ navigation
└─ tool pages
   ├─ SM2
   ├─ SM3
   ├─ SM4
   ├─ RSA
   ├─ DSA
   ├─ Digest
   ├─ MAC
   ├─ Stream
   └─ XOR / utility tools

crypto/
├─ sm2
├─ sm3
├─ sm4
├─ rsa
├─ dsa
├─ digest
├─ mac
└─ stream

shared/
├─ formatting helpers
├─ OpenSSL wrappers/helpers
└─ validation/result helpers
```

Rationale:

- The current file already clusters naturally by algorithm domain.
- Domain separation reduces the blast radius of future changes.
- The UI can stay concerned with collecting input and presenting output, while crypto modules focus on execution and validation.

Alternatives considered:

- Split by button or individual slot only: rejected because it creates many tiny files without improving domain cohesion.
- Keep all crypto logic in the window and extract only helper functions: rejected because the core coupling would remain.

### Decision: Standardize user-facing page composition and feedback

Each calculator page SHALL follow a consistent composition model:

- clearly labeled input controls
- explicit action buttons
- a dedicated result/output region
- space for validation or operation feedback

Rationale:

- Consistent structure is necessary for the application to feel visually intentional.
- It reduces the learning cost when switching between algorithms.
- It creates repeatable implementation patterns for future calculators.

Alternatives considered:

- Let each page evolve independently: rejected because it would preserve inconsistency and reduce the value of the redesign.

## Risks / Trade-offs

- [Large refactor surface] -> Mitigation: implement the shell and modules incrementally, migrating one tool area at a time while keeping feature parity checks in scope.
- [UI redesign may accidentally reduce discoverability for experienced users] -> Mitigation: preserve existing tool coverage and use clear grouping labels rather than hiding functions behind deep navigation.
- [Service extraction may expose inconsistent input/output conventions across algorithms] -> Mitigation: define shared helper patterns for text normalization, hex handling, and result reporting before broad migration.
- [Qt Designer workflow may become harder if too much structure moves into custom widgets] -> Mitigation: keep the shell and reusable UI composition simple, and only introduce custom page widgets where they improve clarity.

## Migration Plan

1. Establish the new application shell and a reusable page composition pattern.
2. Migrate one representative tool area first to validate the page/module split.
3. Extract shared helper code for input normalization, formatting, and error/result handling.
4. Move remaining algorithm areas into page-level UI and domain modules.
5. Remove obsolete monolithic wiring once equivalent functionality is in place.

Rollback strategy:

- If the refactor destabilizes the app, the change can be paused after the shell or after individual page migrations because the work is naturally incremental.
- No data migration is required because the tool has no persistent state model in the current project.

## Open Questions

- Whether navigation should remain tab-based with a redesigned shell or move to a sidebar plus stacked-page arrangement.
- Whether all algorithm domains should migrate in one pass or whether lower-risk domains should be used first as the migration template.
- Whether some current tool areas should be merged or re-labeled for clarity once the new shell is introduced.
