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

### `opcode_window_dword` direction-bit mask
- **Where it showed up:** `xzregh/103340_sshd_find_sensitive_data_base_via_krb5ccname.c` (`opcode_window_dword & 0xfffffffd` when matching XOR reg/reg).
- **Why it mattered:** The mask clears bit 1 to treat opcode direction variants as equivalent; a named mask would clarify intent and keep opcode comparisons consistent across scanners.
- **Notes:** `0xfffffffd` is `~0x2` (direction bit for many 1-byte opcodes such as MOV/XOR). Consider an `X86_OPCODE_MASK_IGNORE_DIR` constant in `metadata/xzre_types.json`, then reuse it in the other opcode scanners that already apply the same mask.

### Packed secret-data descriptor words in SR2 bootstrap
- **Where it showed up:** `xzregh/105410_sshd_recon_bootstrap_sensitive_data.c` (u64 immediates `0x1b000001c8`, `0x1a000001c3`, `0x19000001bd`, plus `0x100000000/0x100000005/0x100000006` adjacent to the `secret_data_append_items_batch` setup).
- **Why it mattered:** These look like bitfield-packed `{operation_slot, bit_cursor}` and `{ordinal, bits_to_shift}` pairs for the 4-entry `secret_data_item_t` batch, but they surface as opaque 64-bit constants in the decomp.
- **Notes:** Likely a stack-typing artifact (array elements flattened into temps). Consider retyping the local as `secret_data_item_t[4]` or adding a helper union for `{bit_cursor, operation_slot}` / `{bits_to_shift, ordinal}` packing so the literals disappear.

### ASCII case-fold mask in SR3 argv dash scan
- **Where it showed up:** `xzregh/1039C0_argv_dash_option_contains_lowercase_d.c` (`window_chars & 0xdf00` when filtering control bytes and non-letter pairs).
- **Why it mattered:** The mask clears the ASCII lowercase bit to normalize both bytes in the 2-char window; naming it would clarify the early-abort conditions for `-d`/`--debug` detection.
- **Notes:** `0xdf00` is `0xDF << 8` (clear bit 0x20 in the high byte). Neighboring literals `0x6400` (`'d'`), `0x0900` (TAB), and `0x3d00` (`'='`) are part of the same scan logic.

### `cmd_arguments_t.control_flags` bitmask in SR4 hooks
- **Where it showed up:** `xzregh/107DE0_sshd_install_mm_log_handler_hook.c` (`control_flags & 0x8` gate, `control_flags & 0x10` filter enable), `xzregh/108270_sshd_monitor_cmd_dispatch.c` (`control_flags & 0x20` socket override, `control_flags & 0x40` PAM disable, `control_flags & 0x1` exit flag, sign-bit wait check via `(char)control_flags`).
- **Why it mattered:** These are stable command-flag bits that already drive log hooking, socket selection, and exit/wait behavior; naming them would eliminate raw hex checks across SR4.
- **Notes:** Consider a `cmd_control_flags_t` enum/bitmask (or bitfield struct) so the decomp can use `CMD_CTRL_*` names instead of literals.

### `cmd_arguments_t.monitor_flags`/`request_flags` low-bit fields in SR4 dispatcher
- **Where it showed up:** `xzregh/108270_sshd_monitor_cmd_dispatch.c` (`monitor_flags & 0x1` continuation gate, `monitor_flags >> 3 & 0xf` socket ordinal, `monitor_flags >> 1/>> 2` for alternate cmd types, `request_flags & 0x1f` socket id, `request_flags & 0x20` sshbuf/KEYALLOWED continuation).
- **Why it mattered:** The low bits encode socket ordinals and continuation behavior, but the current shifts/masks are opaque; naming them would make the command routing rules explicit.
- **Notes:** High bits (`0xC0`) already map to `monitor_payload_source_t`; this entry targets the remaining low-bit fields.

### Syslog mask constants in SR5 log hook
- **Where it showed up:** `xzregh/10A3A0_mm_log_handler_hide_auth_success_hook.c` (`setlogmask(0xff)` while suppressing logs, `setlogmask(0x80000000)` when restoring).
- **Why it mattered:** These are explicit log-mask values (all priorities vs. INT_MIN sentinel) that gate sshd’s syslog suppression; naming them would document the intended mask semantics.
- **Notes:** Consider defining `SYSLOG_MASK_ALL`/`SYSLOG_MASK_SILENCE` (or a small enum) to replace the raw literals.

### Authpassword reply length bit packing in SR5
- **Where it showed up:** `xzregh/108100_mm_answer_authpassword_send_reply_hook.c` (`reply_frame_len_be = (-(cond) & 0xfc000000) + 0x9000000;`).
- **Why it mattered:** The mask toggles between two big-endian length prefixes (0x09 vs 0x05) depending on whether a `root_allowed` dword is included, but the arithmetic obscures that intent.
- **Notes:** Consider replacing the mask expression with named constants like `AUTHREPLY_LEN_BE_WITH_ROOT`/`AUTHREPLY_LEN_BE_NO_ROOT`, or retype the fields so the compiler emits a clearer conditional.

## Completed

### `x86_prefix_state_t.flags_u32` DF16 mask literals in SR1 monitor-field scan
- **Outcome (2025-12-23):** Rewrote `flags_u32` DF16 mask literals in `metadata/xzre_locals.json` to use `DF16_*` names (covering the monitor-field scan plus the audit-flag scanners), refreshed via `./scripts/refresh_xzre_project.sh`, and verified the decomp now emits `DF16_*` masks in `xzregh/102FF0_sshd_find_monitor_field_slot_via_mm_request_send.c`, `xzregh/104AE0_find_l_audit_any_plt_mask_and_slot.c`, and `xzregh/104EE0_find_l_audit_any_plt_mask_via_symbind_alt.c`.

### `DT_FLAGS`/`DT_FLAGS_1` bind-now bits
- **Outcome (2025-12-22):** Added `ElfDynamicFlags`/`ElfDynamicFlags1` enums (`DF_BIND_NOW`, `DF_1_NOW`) in `metadata/xzre_types.json`, rewrote the bind-now bit tests in `metadata/xzre_locals.json`, refreshed via `./scripts/refresh_xzre_project.sh`, and verified `xzregh/1013D0_elf_info_parse.c` uses the named DF_* constants.

### `Elf64_Phdr::p_flags` PF_* segment-permission mask
- **Outcome (2025-12-22):** Added `ElfProgramHeaderFlags`/`ElfProgramHeaderFlags_t` in `metadata/xzre_types.json`, retyped `Elf64_Phdr.p_flags` plus the `elf_vaddr_range_has_pflags` prototypes, rewrote PF_* mask literals in `metadata/xzre_locals.json`, refreshed via `./scripts/refresh_xzre_project.sh`, and verified the exported `xzregh/*.c` uses `PF_*` names.

### `Elf64_Rela::r_info` packed symbol/type fields
- **Outcome (2025-12-22):** Added `Elf64RelocInfoConstants` (`ELF64_R_TYPE_MASK`, `ELF64_R_SYM_SHIFT`) in `metadata/xzre_types.json`, rewrote the `r_info` mask/shift uses via `metadata/xzre_locals.json`, refreshed via `./scripts/refresh_xzre_project.sh`, and confirmed `xzregh/101DC0_elf_find_import_reloc_slot.c` uses the named constants.

### `Elf64_Relr` bitmap vs literal entry bit
- **Outcome (2025-12-22):** Added `ElfRelrEntryFlags`/`ElfRelrBitmapConstants` in `metadata/xzre_types.json`, rewrote the RELR entry type/shift/stride literals via `metadata/xzre_locals.json`, refreshed via `./scripts/refresh_xzre_project.sh`, and confirmed `xzregh/101C30_elf_relr_find_relative_slot.c` uses `ELF64_RELR_IS_BITMAP`/`ELF64_RELR_BITMAP_*`.

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
