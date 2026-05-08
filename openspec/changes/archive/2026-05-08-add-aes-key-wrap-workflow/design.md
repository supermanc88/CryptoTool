## Context

The AES page currently follows a block-cipher mental model: mode, padding, IV or nonce, AAD, tag, input, and output. That model works for `ECB / CBC / CTR / GCM`, but it is the wrong abstraction for AES key wrap. Key wrap is not simply another cipher mode; it is a different kind of operation with a key-encryption-key, key material to wrap or unwrap, and variant-specific constraints such as standard wrap versus padded wrap.

The user wants this capability on the AES page, which is a good fit from a product perspective, but the implementation needs to avoid corrupting the current block-cipher workflow with fields that stop making sense for key wrap.

## Goals / Non-Goals

**Goals:**
- Add AES key wrap support directly to the AES page.
- Keep block-cipher and key-wrap workflows clearly separated in the UI.
- Support both `AES-KW` and `AES-KWP`.
- Support both wrapping and unwrapping of key material.
- Keep explicit validation and user-facing errors for invalid lengths or malformed wrapped data.

**Non-Goals:**
- Do not model key wrap as just another entry in the existing block-cipher `mode` selector.
- Do not change the top-level `块加密运算` navigation model.
- Do not add unrelated key-management features such as PEM export, ASN.1 parsing, or KEK derivation.
- Do not merge AES key wrap into the SM4 workflow.

## Decisions

### 1. Add an AES operation-type switch instead of overloading the existing mode selector

The AES page should distinguish between `Block Cipher` and `Key Wrap` as top-level operation types inside the AES workspace.

Why this over adding `KW / KWP` to the current mode combo:
- Key wrap does not use the same field model as ordinary block modes.
- The current `IV / AAD / tag / padding` controls would become misleading or irrelevant.
- It keeps the existing cipher workflow stable and understandable.

Alternative considered:
- Add `KW` and `KWP` directly to the AES mode list. Rejected because it mixes two different operation families into one parameter surface.

### 2. Treat key wrap as its own workflow with KEK-specific field naming

The key wrap layout should use fields such as `KEK`, `Plain Key Material`, and `Wrapped Key`, rather than reusing the generic `Key / Input / Output` labels without qualification.

Why this over generic field reuse:
- Users need to understand immediately which key is the wrapping key and which key material is being wrapped.
- It reduces operator error in a tool that is explicitly about crypto material manipulation.

Alternative considered:
- Reuse existing AES field names and rely on helper text. Rejected because the semantics are too easy to misread.

### 3. Support both AES-KW and AES-KWP in the first delivery

The first version should expose both standard key wrap and padded key wrap as explicit variants.

Why this over shipping only AES-KW first:
- The OpenSSL environment already exposes both variants.
- `AES-KWP` is the practical path when the input length is not a clean 64-bit multiple.
- A simple variant selector keeps the UI explicit without much extra complexity.

Alternative considered:
- Support only `AES-KW`. Rejected because it leaves an obvious capability gap and forces awkward input constraints immediately.

### 4. Keep service separation explicit

The AES implementation should keep ordinary block-cipher processing and key-wrap processing as separate service paths, even if they live under the same AES service namespace.

Why this over one overloaded `process(...)` entrypoint:
- The parameter model is materially different.
- Validation rules are different.
- It is easier to test and reason about wrap versus cipher behavior when the code paths are explicit.

Alternative considered:
- Extend the current AES process function with more conditional arguments. Rejected because it would quickly become ambiguous and brittle.

## Risks / Trade-offs

- [AES page gets too busy] → Separate block-cipher and key-wrap operation types clearly and show only the relevant layout for the active type.
- [Users confuse KEK with wrapped key material] → Use explicit field names and helper text that reflect wrap semantics.
- [Variant-specific constraints create surprising errors] → Validate lengths and malformed wrapped input directly with clear messages.
- [Service API becomes messy] → Keep key-wrap processing on a distinct code path rather than adding more optional parameters to the current AES cipher flow.

## Migration Plan

1. Add an operation-type switch to the AES page.
2. Preserve the existing block-cipher layout for the current AES workflow.
3. Add a dedicated key-wrap layout with variant selection and `Wrap / Unwrap` actions.
4. Implement AES key-wrap service logic for `AES-KW` and `AES-KWP`.
5. Verify that the existing AES block-cipher workflow still behaves the same and that key-wrap operations behave independently.

Rollback is straightforward: remove the key-wrap branch and keep the existing AES block-cipher path only.

## Open Questions

- Should the AES page preserve separate field state for `Block Cipher` and `Key Wrap` when switching between them?
- Do we want to expose inverse algorithm names anywhere, or keep the UI phrased only as `Wrap / Unwrap`?
