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

### `Elf64_Relr` bitmap vs literal entry bit
- **Where it showed up:** `xzregh/101C30_elf_relr_find_relative_slot.c` (`relr_entry & 1` selects bitmap vs literal entries; `relr_entry >> 1` iterates the bitmap bits).
- **Why it mattered:** The LSB encodes RELR entry type (literal pointer vs 63-bit bitmap); naming the bit makes the packed-RELR walk easier to follow.
- **Notes:** Consider constants like `ELF64_RELR_IS_BITMAP = 1` plus a named shift/stride (`bitmap_shift = 1`, `bitmap_stride = 0x1f8` for 63 slots).

### `Elf64_Rela::r_info` packed symbol/type fields
- **Where it showed up:** `xzregh/101DC0_elf_find_import_reloc_slot.c` (`relocs->r_info & 0xffffffff` for type, `relocs->r_info >> 0x20` for symbol index).
- **Why it mattered:** These are the standard ELF64_R_TYPE/ELF64_R_SYM bitfields; naming them removes the `0xffffffff`/shift literals.
- **Notes:** Define helpers or constants (`ELF64_R_TYPE_MASK = 0xffffffff`, `ELF64_R_SYM_SHIFT = 32`) and rewrite the accesses via locals metadata.

### `Elf64_Phdr::p_flags` PF_* segment-permission mask
- **Where it showed up:** `xzregh/101240_elf_vaddr_range_has_pflags_impl.c` (`(p_flags & p_flags) == p_flags`), `xzregh/1013D0_elf_info_parse.c` (`elf_vaddr_range_has_pflags(..., 4)`), `xzregh/101EC0_elf_get_text_segment.c` (`p_flags & 1`), `xzregh/101F70_elf_get_rodata_segment_after_text.c` (`(p_flags & 7) == 4`), `xzregh/102150_elf_get_writable_tail_span.c` (`(p_flags & 7) == 6`), `xzregh/1022D0_elf_vaddr_range_in_relro_if_required.c` (`elf_vaddr_range_has_pflags(..., 2)`).
- **Why it mattered:** The literals correspond to PF_X/PF_W/PF_R combinations; naming them would clarify segment-permission tests and avoid duplicated masks.
- **Notes:** Consider a bitmask enum (e.g., `ElfProgramHeaderFlags` with `PF_X=1`, `PF_W=2`, `PF_R=4`) plus locals rewrites for readability.

### `DT_FLAGS`/`DT_FLAGS_1` bind-now bits
- **Where it showed up:** `xzregh/1013D0_elf_info_parse.c` (`DT_FLAGS` uses `& 8`, `DT_FLAGS_1` uses `& 1` before setting `feature_flags |= 0x20`).
- **Why it mattered:** These are standard `DF_BIND_NOW` and `DF_1_NOW` bits; naming them ties the gate to the ELF spec and avoids opaque literals.
- **Notes:** Model `DF_*` constants or `ElfDynamicFlags`/`ElfDynamicFlags1` enums and replace the bit tests in the parser.

## Completed

### GNU hash chain end-of-chain bit
- **Outcome (2025-12-22):** Added `GnuHashChainFlags` (`GNU_HASH_CHAIN_END`) in `metadata/xzre_types.json`, rewrote the chain-walk terminator via `metadata/xzre_locals.json`, refreshed via `./scripts/refresh_xzre_project.sh`, and confirmed `xzregh/101880_elf_gnu_hash_lookup_symbol.c` uses `GNU_HASH_CHAIN_END`.

### `Elf64_Versym` version-index/hidden-bit masks
- **Outcome (2025-12-22):** Added `ElfVersymFlags`/`ElfVersymFlags_t` in `metadata/xzre_types.json`, rewrote versym mask literals in `metadata/xzre_locals.json`, refreshed via `./scripts/refresh_xzre_project.sh`, and verified `xzregh/101880_elf_gnu_hash_lookup_symbol.c` now uses `VERSYM_VERSION_*` names.

### `elf_info_t.feature_flags` optional-table bitmask
- **Where it showed up:** `xzregh/1013D0_elf_info_parse.c` (sets `| 1/2/4/8/0x10/0x20`), `xzregh/101E60_elf_find_plt_reloc_slot.c` (`feature_flags & 1`), `xzregh/101E90_elf_find_got_reloc_slot.c` (`& 2`), `xzregh/101C30_elf_relr_find_relative_slot.c` (`& 4`), `xzregh/101880_elf_gnu_hash_lookup_symbol.c` (`& 0x18`), `xzregh/104660_scan_link_map_and_init_shared_libs.c` (`& 0x20`).
- **Why it mattered:** The mask encodes which optional ELF tables/behaviors are present (PLT/RELA/RELR/VERDEF/VERSYM/BIND_NOW); naming the bits removes the magic constants and makes feature gating obvious.
- **Outcome (2025-12-22):** Added `ElfFlags_t` storage, retyped `elf_info_t.feature_flags`, and refreshed via `./scripts/refresh_xzre_project.sh` so the decomp uses `X_ELF_*` names.

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
