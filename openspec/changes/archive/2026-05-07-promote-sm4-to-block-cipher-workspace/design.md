## Context

The current application shell uses one left-side navigation item per page, and `SM4` already exists as an independent page component with a mature block-cipher workflow. The user now wants to add `AES`, but doing that as another top-level page would make the navigation more fragmented and keep mixing concrete algorithms with broader workspaces.

This is a good restructuring point because `SM4` and `AES` are close enough in user workflow to live under one entry, but not identical enough to force into a single fully abstracted form on day one. The design needs to improve information architecture without creating a large, brittle “universal symmetric crypto” page.

## Goals / Non-Goals

**Goals:**
- Replace the top-level `SM4` entry with a `块加密运算` workspace entry.
- Keep `SM4` as the first concrete algorithm under that workspace.
- Add `AES` as the second concrete algorithm under the same workspace.
- Reuse the visual and interaction patterns that already work for `SM4`.
- Keep `Stream` separate so the scope stays block-cipher-specific.

**Non-Goals:**
- Do not merge `Stream` into this workspace.
- Do not build a generic “all symmetric algorithms” page in this change.
- Do not force SM4 and AES through one overly abstract service if their mode or validation differences make the code harder to reason about.
- Do not redesign unrelated pages such as `MAC`, `digest`, `SM2`, or `RSA`.

## Decisions

### 1. Promote SM4 into a workspace-level entry called `块加密运算`

The left navigation will expose one capability-oriented entry for block ciphers instead of a concrete `SM4` entry.

Why this over adding a separate `AES` top-level item:
- It keeps the navigation aligned with capability-oriented entries already present in the product.
- It avoids growing a flat algorithm list indefinitely.
- It makes `AES` feel like a natural expansion of an existing area rather than a one-off addition.

Alternative considered:
- Keep `SM4` and add `AES` beside it. Rejected because it increases navigation clutter and keeps the classification inconsistent.

### 2. Use one workspace container with explicit child algorithm switching

The block cipher entry should host a parent workspace container and expose a lightweight algorithm switch such as `SM4 | AES` inside the page.

Why this over two completely independent first-level pages:
- The user enters the product through the category they mean: block cipher operations.
- The workspace can share hero language, visual framing, and future common actions.
- It leaves room for more block ciphers later without changing the main navigation again.

Alternative considered:
- Use nested navigation in the main sidebar. Rejected because the current shell is a flat single-column list and this would introduce a larger navigation refactor than needed.

### 3. Keep algorithm-specific pages or subviews behind the shared workspace

The first implementation should treat `SM4` and `AES` as sibling algorithm views inside a block-cipher workspace container, rather than forcing one giant universal form immediately.

Why this over one totally unified form from the start:
- `SM4` already has a working page structure worth preserving.
- `AES` will likely differ on key-size expectations and supported mode semantics.
- A container with algorithm-specific subviews is easier to reason about than a page full of `if algorithm == ...` branches.

Alternative considered:
- One fully unified `BlockCipherPage` with all logic inline. Rejected for initial scope because it increases branching and raises the risk of a confusing UI.

### 4. Introduce AES with representative block and AEAD coverage

AES support should follow the same general workflow shape as SM4 and cover representative operational modes rather than an unbounded mode matrix.

Why this over trying to support every OpenSSL AES variant immediately:
- It keeps the first implementation testable and coherent.
- It matches the current application style, which favors practical workspaces over exhaustive reference tools.
- It reduces the risk of exposing obscure or weak defaults.

Alternative considered:
- Add every available AES cipher and mode. Rejected because it expands validation, UI branching, and user confusion disproportionately.

## Risks / Trade-offs

- [Workspace becomes a thin wrapper with duplicated child pages] → Accept this initially if it keeps behavior explicit; extract common layout pieces only where reuse is real.
- [AES and SM4 diverge too much for shared framing] → Keep a container-plus-subview model so divergence stays localized.
- [Users expect `Stream` under the same entry] → Use precise naming (`块加密运算` / `Block Cipher Workspace`) and keep `Stream` separate in navigation.
- [Algorithm switch increases page complexity] → Use a small, obvious in-page switch and keep the rest of the layout stable.
- [Future block ciphers pressure the container design] → Treat this change as establishing the pattern for adding more block ciphers later.

## Migration Plan

1. Replace the main navigation label and routing from `SM4` to `块加密运算`.
2. Introduce a workspace container that can host algorithm-specific block-cipher views.
3. Mount the existing SM4 experience inside that workspace as the initial child view.
4. Add AES service logic and an AES child view using the same overall interaction model.
5. Verify navigation, converter integration, and block-cipher workflows without changing the `Stream` page.

Rollback is straightforward: revert the navigation label and route the old SM4 page back to the first-level shell entry, then remove the AES additions.

## Open Questions

- Which AES modes belong in the first delivery: only ECB/CBC/CTR/GCM, or a broader set matching most of SM4’s current list?
- Should the in-page algorithm switch be segmented buttons or a compact combo box?
- How much of the existing SM4 layout should be extracted into shared block-cipher page chrome during the first pass?
