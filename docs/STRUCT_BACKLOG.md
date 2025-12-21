# Struct Backlog

Structs (and struct-like overlays) we still need to model cleanly in `metadata/xzre_types.json`. Track active work here just like the enum backlog so we avoid duplicating effort.

## Workflow
- Confirm the struct layout by reviewing the affected `xzregh/*.c` decompilation plus any helper headers/scripts (search for `field0_0x0`/`._N_M_` accesses that hint at missing metadata).
- Update `metadata/xzre_types.json` with the refined struct definition (and `metadata/xzre_locals.json` whenever locals/register temps need the new type).
- Run `./scripts/refresh_xzre_project.sh` (or `--check-only`) so Ghidra picks up the struct, rewrites the exported `.c` files, and validates that `ghidra_scripts/generated/xzre_autodoc.json` stays in sync.
- Note the outcome here (strike-through, notes, or follow-ups) plus bump the relevant entries in `docs/STRUCT_PROGRESS.md` when a struct receives a focused pass.

## Candidates

### `dasm_ctx_t` opcode-window dword alias
- **Where it shows up:** `xzregh/104AE0_find_l_audit_any_plt_mask_and_slot.c` (`insn_ctx._40_4_` comparisons).
- **Why it matters:** The audit scanner still relies on raw `_40_4_` slices for opcode checks; adding a named alias keeps the pattern logic readable.
- **Reverse-engineering plan:** Add a union/overlay in `dasm_ctx_t` for the opcode-window dword (e.g., `u32 opcode_window_dword` tied to `opcode_window[4]`), update locals to rewrite `insn_ctx._40_4_`, and validate via `./scripts/refresh_xzre_project.sh`.
- **Status (2025-12-20):** Pending – `_40_4_` slice still appears in the audit helper.

### `instruction_register_bitmap_t` high-word alias
- **Where it shows up:** `xzregh/104EE0_find_l_audit_any_plt_mask_via_symbind_alt.c` (`mask_register_bitmap.raw_value._2_2_`).
- **Why it matters:** The register bitmap still uses a raw half-word slice; adding a named high-word view keeps the bitmap manipulation readable.
- **Reverse-engineering plan:** Add a `u16 high_word`/`u16 high_bytes` overlay in `instruction_register_bitmap_t`, update locals to prefer the named field, and validate via `./scripts/refresh_xzre_project.sh`.
- **Status (2025-12-21):** Done – added a high-word overlay for `instruction_register_bitmap_t` and rewired the raw slice in `find_l_audit_any_plt_mask_via_symbind_alt`, refresh clean.
