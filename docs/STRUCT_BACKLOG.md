# Struct Backlog

Structs (and struct-like overlays) we still need to model cleanly in `metadata/xzre_types.json`. Track active work here just like the enum backlog so we avoid duplicating effort.

## Workflow
- Confirm the struct layout by reviewing the affected `xzregh/*.c` decompilation plus any helper headers/scripts (search for `field0_0x0`/`._N_M_` accesses that hint at missing metadata).
- Update `metadata/xzre_types.json` with the refined struct definition (and `metadata/xzre_locals.json` whenever locals/register temps need the new type).
- Run `./scripts/refresh_xzre_project.sh` (or `--check-only`) so Ghidra picks up the struct, rewrites the exported `.c` files, and validates that `ghidra_scripts/generated/xzre_autodoc.json` stays in sync.
- Note the outcome here (strike-through, notes, or follow-ups) plus bump the relevant entries in `docs/STRUCT_PROGRESS.md` when a struct receives a focused pass.

## Candidates

### `dasm_opcode_window_t` high-byte overlay
- **Where it shows up:** `xzregh/100020_x86_decode_instruction.c` (`vex_prefix_window.opcode_window_dword._1_3_` and `opcode_window_seed.opcode_window_dword._1_3_`).
- **Why it matters:** The decoder still emits raw `_1_3_` byte-slice writes; a named overlay keeps the opcode-window initialization readable.
- **Reverse-engineering plan:** Add a byte-level overlay inside `dasm_opcode_window_t` (e.g., `{ u8 low_byte; u8 high_bytes[3]; }`) and update locals to rewrite `_1_3_` to the new field (or to `opcode_window[1..3]` if the decompiler cooperates), then validate via `./scripts/refresh_xzre_project.sh`.
- **Status (2025-12-21):** Open – identified the remaining raw slice in the decoder.

## Completed

### `dasm_ctx_t` opcode-window dword alias
- **Where it showed up:** `xzregh/104AE0_find_l_audit_any_plt_mask_and_slot.c` (`insn_ctx._40_4_` comparisons).
- **Why it mattered:** The audit scanner still relied on raw `_40_4_` slices for opcode checks.
- **Outcome (2025-12-21):** Done – added the opcode-window dword overlay in `dasm_ctx_t`, rewired the audit helper to use it, refresh clean.

### `instruction_register_bitmap_t` high-word alias
- **Where it showed up:** `xzregh/104EE0_find_l_audit_any_plt_mask_via_symbind_alt.c` (`mask_register_bitmap.raw_value._2_2_`).
- **Why it mattered:** The register bitmap still used a raw half-word slice.
- **Outcome (2025-12-21):** Done – added a high-word overlay for `instruction_register_bitmap_t` and rewired the raw slice in `find_l_audit_any_plt_mask_via_symbind_alt`, refresh clean.
