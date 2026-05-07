## Context

The current `块加密运算` implementation already has the right information architecture: one top-level workspace entry containing both `SM4` and `AES`. The remaining problem is composition. Today the workspace hosts algorithm-specific page widgets, and each of those widgets still owns its own page shell and scrolling behavior. That produces nested scroll areas and makes the algorithm switch feel like changing subpages instead of changing one workspace’s active mode.

The user wants the interaction to feel flatter: one page, one scrolling surface, one stable workspace context, and only the algorithm-specific layout region changing when `SM4` or `AES` is selected.

## Goals / Non-Goals

**Goals:**
- Collapse the block cipher workspace into a single page-level scroll context.
- Keep the `SM4 / AES` switch inside the workspace while eliminating page-level nesting.
- Preserve the existing block-cipher operational capabilities and explicit converter actions.
- Make algorithm changes feel like an in-place layout swap rather than a page transition.

**Non-Goals:**
- Do not revert the `块加密运算` top-level navigation change.
- Do not merge `Stream` into the block cipher workspace.
- Do not redesign the crypto services away from separate `SM4` and `AES` implementations unless needed for local cleanup.
- Do not introduce a generic universal crypto form for unrelated algorithm families.

## Decisions

### 1. Keep one workspace page and remove page-level algorithm children

`BlockCipherWorkspacePage` should remain the top-level widget for the `块加密运算` entry, but `SM4` and `AES` should stop being mounted as full page widgets with their own scroll shells.

Why this over keeping the current container-plus-pages structure:
- It removes nested scrolling at the architectural source rather than trying to tune wheel behavior.
- It makes the workspace feel like one tool with multiple modes instead of a page that contains other pages.
- It preserves the navigation model that was just introduced.

Alternative considered:
- Keep subpages and try to patch scroll behavior. Rejected because it treats the symptom rather than the layout model.

### 2. Switch layouts in place inside one content region

The workspace should own a shared shell and one content host, and switching `SM4 / AES` should swap the active algorithm layout inside that host.

Why this over routing through nested `QStackedWidget` pages with full page chrome:
- The user stays in one stable context with one title, one scroll position model, and one set of surrounding controls.
- Shared workspace elements such as hero text and algorithm switching remain visually stable.
- It clarifies which parts are global workspace framing versus algorithm-specific content.

Alternative considered:
- Flatten both algorithms into one giant always-present form. Rejected because it would create too much branching and hidden conditional complexity.

### 3. Downgrade algorithm views from pages to content components

`SM4` and `AES` should be treated as embeddable content regions or algorithm panes rather than self-contained page widgets.

Why this over keeping `Sm4Page` and `AesPage` semantics unchanged:
- Page widgets naturally want to own page shell concerns such as scroll areas, outer margins, and hero sections.
- Content components can focus on algorithm-specific controls, actions, and results.
- This keeps the workspace architecture coherent while still allowing separation of concerns.

Alternative considered:
- Keep the same classes and suppress their internal scroll areas. Rejected as a first choice because it preserves a misleading abstraction boundary.

## Risks / Trade-offs

- [Refactor touches both workspace and algorithm UI layers] → Keep crypto services stable and limit the change to view composition.
- [Shared shell becomes too opinionated for algorithm-specific needs] → Limit the shared shell to page framing and leave field groups local to each algorithm content component.
- [Switching layouts may reset context in surprising ways] → Keep the algorithm switch explicit and decide whether to preserve or clear per-algorithm field state intentionally.
- [Refactor pressure may encourage over-abstraction] → Prefer straightforward content-region composition over a universal dynamic form engine.

## Migration Plan

1. Replace the current nested page composition inside `BlockCipherWorkspacePage` with one outer scroll shell and one content host.
2. Refactor `SM4` and `AES` UI code into embeddable content components or build methods that do not own page-level scrolling.
3. Reconnect converter actions and status reporting through the flattened workspace composition.
4. Verify that `SM4 / AES` switching no longer feels like moving between nested pages and that scroll behavior is stable.

Rollback is straightforward: restore the previous child-page composition inside `BlockCipherWorkspacePage`.

## Open Questions

- Should each algorithm preserve its own field state when switching away and back, or should the workspace rebuild from a clean state?
- Is it worth extracting a shared block-cipher content base now, or should the first pass only flatten the layout and keep duplication modest?
