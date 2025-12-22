# Flag Backlog

Flag, bitmask, and bitfield candidates we still need to model cleanly in
`metadata/xzre_types.json`. Track active work here just like the enum/struct
backlogs so we avoid duplicating effort.

## Workflow
- Confirm the flag or bitmask candidate by reviewing the affected
  `xzregh/*.c` decompilation (look for repeated `&`, `|`, shifts, or literal
  masks that imply named bits).
- Define the flag set in `metadata/xzre_types.json` (enum with bit values or
  bitfield structs) and update `metadata/xzre_locals.json` when you want
  replacements in the decomp.
- Run `./scripts/refresh_xzre_project.sh` (or `--check-only`) so Ghidra picks
  up the flag types, rewrites the exported `.c` files, and validates that
  `ghidra_scripts/generated/xzre_autodoc.json` stays in sync.
- Note the outcome here (strike-through, notes, or follow-ups) plus bump the
  relevant entries in `docs/STRUCT_PROGRESS.md` if a flag change also updates
  a struct layout.

## Candidates

## Completed

### `x86_prefix_state_t.flags_u16` combined prefix-state mask
- **Where it showed up:** `xzregh/10AC40_find_reg_to_reg_instruction.c` (`(prefix.flags_u16 & 0xf80) == 0`).
- **Why it mattered:** The combined mask is used to assert “no SIB/disp/imm/prefix side effects” before accepting reg↔reg ops, but it is still a magic literal.
- **Notes:** `flags_u16` overlays `decoded.flags` and `decoded.flags2`, so this mask likely covers the “has immediate/disp/SIB” bits across both bytes.
- **Outcome (2025-12-22):** Added `InstructionFlags16`/`InstructionFlags16_t` and rewrote flags_u16 masks (including the SIB/disp/imm combo) to use `DF16_*` names; refreshed via `./scripts/refresh_xzre_project.sh`.

### `x86_prefix_state_t.modrm_bytes.rex_byte` REX bitmask
- **Where it showed up:** `xzregh/100020_x86_decode_instruction.c` (REX synthesized from VEX using `| 1`, `| 2`, and `| 8`, plus raw REX capture for 0x4x prefixes), `xzregh/100D40_find_riprel_mov_or_lea.c`, `xzregh/100E00_find_riprel_mov.c`, `xzregh/100F60_find_riprel_lea.c`, `xzregh/102C60_find_riprel_mov_load_target_in_range.c`, `xzregh/102D30_elf_build_string_xref_table.c` (`(rex_byte & 0x48) == 0x48` width checks), `xzregh/10AC40_find_reg_to_reg_instruction.c` (`rex_byte & 0x05` to exclude REX.R/REX.B).
- **Why it mattered:** A named `REX_*` bitmask would make the VEX-to-REX mapping and register-extension logic explicit.
- **Notes:** The opcode scanners treat `0x48` as “REX present + W set” for 64-bit operand width, and `0x05` as the “no REX.R/REX.B” filter for reg-only ops.
- **Outcome (2025-12-22):** Added `RexPrefixFlags` storage for REX bits, retyped `rex_byte`, rewrote REX bit checks/combines to use `REX_*` names across decoder/scanner exports, and refreshed via `./scripts/refresh_xzre_project.sh`.

### `x86_prefix_state_t.decoded.flags` prefix/decoder flags
- **Where it showed up:** `xzregh/100020_x86_decode_instruction.c` (bit tests + ORs against `0x1/0x2/0x4/0x8/0x10/0x20/0x40/0xc0`, plus sign-bit checks for SIB handling).
- **Why it mattered:** Naming the prefix bits would make the decoder readable (lock/rep, segment override, operand/address size, VEX/REX seen, ModRM/SIB present) and help downstream scanners reason about the decoded instruction state.
- **Outcome (2025-12-22):** Done – added `InstructionFlags_t` storage for DF1 bits, rewrote `decoded.flags` checks/sets to use `DF1_*` names in the decoder and scanners, and refreshed exports.

### `x86_prefix_state_t.decoded.flags2` displacement/immediate flags
- **Where it showed up:** `xzregh/100020_x86_decode_instruction.c` (flags2 drives disp8/disp32 selection, immediate parsing, and MOV r64,imm64 handling), `xzregh/100EB0_find_lea_with_displacement.c` (`(flags2 & 7) == 1` fast path for disp32-only LEA), `xzregh/101060_find_riprel_opcode_memref_ex.c`, `xzregh/101170_find_riprel_grp1_imm8_memref.c`, `xzregh/102C60_find_riprel_mov_load_target_in_range.c` (require `flags2 & 1` before recomputing RIP-relative displacements).
- **Why it mattered:** These bits gate how many bytes the decoder consumes for displacement/immediates; naming them makes the parse flow and downstream scans clearer.
- **Outcome (2025-12-22):** Done – added `InstructionFlags2_t` storage, rewrote `flags2` checks/sets to use `DF2_*` names in decoder/scanner exports, and refreshed via `./scripts/refresh_xzre_project.sh`.
