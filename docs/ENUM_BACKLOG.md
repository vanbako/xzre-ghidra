# Enum Backlog

Enum candidates we still need to model cleanly in `metadata/xzre_types.json`. Track active work here just like the struct backlog so we avoid duplicating effort.

## Workflow
- Confirm the enum candidate by reviewing the affected `xzregh/*.c` decompilation (look for repeated literal comparisons or switch cases that imply a fixed set of values).
- Add the enum definition to `metadata/xzre_types.json` (and update `metadata/xzre_locals.json` when you want replacements in the decomp).
- Run `./scripts/refresh_xzre_project.sh` (or `--check-only`) so Ghidra picks up the enum, rewrites the exported `.c` files, and validates that `ghidra_scripts/generated/xzre_autodoc.json` stays in sync.
- Note the outcome here (strike-through, notes, or follow-ups) plus bump the relevant entries in `docs/STRUCT_PROGRESS.md` if an enum change also updates struct documentation.

## Candidates

## Completed

### ELF relocation types (R_X86_64_*)
- **Where it showed up:** `xzregh/101E60_elf_find_plt_reloc_slot.c` (reloc type 7), `xzregh/101E90_elf_find_got_reloc_slot.c` (reloc type 6), and `xzregh/101B90_elf_rela_find_relative_slot.c` (`r_info == 8`).
- **Why it mattered:** Naming R_X86_64_JUMP_SLOT/GLOB_DAT/RELATIVE clarifies the loader’s relocation handling and avoids magic constants.
- **Outcome (2025-12-22):** Done – added `x86_64_reloc_type_t` with R_X86_64_GLOB_DAT/JUMP_SLOT/RELATIVE, rewrote relocation literals via locals replacements, and refreshed exports.

### ELF program header types (PT_*)
- **Where it showed up:** `xzregh/1013D0_elf_info_parse.c` (`p_type == 1/2` plus PT_GNU_RELRO checks), `xzregh/1013B0_is_pt_gnu_relro.c` (obfuscated PT_GNU_RELRO test), and the PT_LOAD scans in `xzregh/101EC0_elf_get_text_segment.c`, `xzregh/102150_elf_get_writable_tail_span.c`, `xzregh/101F70_elf_get_rodata_segment_after_text.c`, `xzregh/101240_elf_vaddr_range_has_pflags_impl.c`.
- **Why it mattered:** Naming PT_LOAD/PT_DYNAMIC/PT_GNU_RELRO makes the ELF parser easier to read and keeps segment-type checks consistent.
- **Outcome (2025-12-22):** Done – added `ElfProgramHeaderType` with PT_LOAD/PT_DYNAMIC/PT_GNU_RELRO, rewrote the program-header comparisons via locals replacements (including the obfuscated RELRO constant), and refreshed exports.

### OpenSSH sshkey type IDs (KEY_*)
- **Where it showed up:** `xzregh/107630_verify_ed448_signed_payload.c` (`sshkey->type` compared against 0/1/2/3 for RSA/DSA/ECDSA/ED25519).
- **Why it mattered:** Naming KEY_* values makes key-type branching explicit and aligns with upstream OpenSSH headers.
- **Outcome (2025-12-22):** Done – added `sshkey_type_t` (KEY_RSA/DSA/ECDSA/ED25519), retyped `sshkey.type` plus the local `status`, and refreshed exports.

### ELF dynamic tag IDs
- **Where it showed up:** `xzregh/1013D0_elf_info_parse.c` (switch/cases for 2, 5, 6, 7, 8, 0x17, 0x18, 0x1e, 0x23, 0x24; plus comparisons for 0x6ffffef5, 0x6ffffff0, 0x6ffffffb, 0x6ffffffc, 0x6ffffffd, 0x7fffffff).
- **Why it mattered:** These are canonical DT_* tags; naming them makes the ELF parser readable and keeps tag lookups consistent across helpers.
- **Outcome (2025-12-21):** Done – added `ElfDynamicTag`, rewrote the tag literals in `elf_info_parse`, and refreshed exports.

### CPUID leaf IDs
- **Where it showed up:** `xzregh/10A700_cpuid_query_and_unpack.c` (leaf values 0..10, 0xb, 0xd, 0xf, 0x80000002–0x80000004).
- **Why it mattered:** These are well-defined CPUID leaves; an enum clarifies which pseudo-leaf helper is intended.
- **Outcome (2025-12-21):** Done – added `cpuid_leaf_t`, retyped CPUID leaf parameters, and refreshed exports so comparisons use named constants.

### RIP-relative ModRM signature constants
- **Where it showed up:** `xzregh/100D40_find_riprel_mov_or_lea.c`, `xzregh/100E00_find_riprel_mov.c`, `xzregh/100F60_find_riprel_lea.c`, `xzregh/101060_find_riprel_opcode_memref_ex.c`, `xzregh/102C60_find_riprel_mov_load_target_in_range.c`, `xzregh/103340_sshd_find_sensitive_data_base_via_krb5ccname.c` (mask checks against `0x5000000` and related patterns).
- **Why it mattered:** These constants encode specific ModRM patterns (RIP-relative disp32); naming them avoids repeated magic masks across the opcode scanners.
- **Outcome (2025-12-21):** Done – added `dasm_modrm_signature` constants, rewrote ModRM mask checks via locals, refreshed exports.

### Monitor payload source mode (cmd_type 3)
- **Where it showed up:** `xzregh/108270_sshd_monitor_cmd_dispatch.c` (`monitor_flags & 0xc0` with values 0x00/0x40/0x80/0xc0).
- **Why it mattered:** The high bits select how cmd_type 3 sources payloads; a named enum clarifies the control flow and avoids ambiguous bit masks.
- **Outcome (2025-12-21):** Done – added `monitor_payload_source_t`, rewrote the monitor flag comparisons in `sshd_monitor_cmd_dispatch`, and refreshed exports.
