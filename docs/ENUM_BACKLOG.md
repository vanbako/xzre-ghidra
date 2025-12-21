# Enum Backlog

Enum candidates we still need to model cleanly in `metadata/xzre_types.json`. Track active work here just like the struct backlog so we avoid duplicating effort.

## Workflow
- Confirm the enum candidate by reviewing the affected `xzregh/*.c` decompilation (look for repeated literal comparisons or switch cases that imply a fixed set of values).
- Add the enum definition to `metadata/xzre_types.json` (and update `metadata/xzre_locals.json` when you want replacements in the decomp).
- Run `./scripts/refresh_xzre_project.sh` (or `--check-only`) so Ghidra picks up the enum, rewrites the exported `.c` files, and validates that `ghidra_scripts/generated/xzre_autodoc.json` stays in sync.
- Note the outcome here (strike-through, notes, or follow-ups) plus bump the relevant entries in `docs/STRUCT_PROGRESS.md` if an enum change also updates struct documentation.

## Candidates

### ELF dynamic tag IDs
- **Where it shows up:** `xzregh/1013D0_elf_info_parse.c` (switch/cases for 2, 5, 6, 7, 8, 0x17, 0x18, 0x1e, 0x23, 0x24; plus comparisons for 0x6ffffef5, 0x6ffffff0, 0x6ffffffb, 0x6ffffffc, 0x6ffffffd, 0x7fffffff).
- **Why it matters:** These are canonical DT_* tags; naming them makes the ELF parser readable and keeps tag lookups consistent across helpers.
- **Reverse-engineering plan:** Add an enum (e.g., `ElfDynamicTag`) with the DT_* and GNU/OS-specific tags used here; replace literals in `elf_info_parse` via locals rewrites; refresh.
- **Status (2025-12-21):** Open – identified the dynamic tag literals.

### CPUID leaf IDs
- **Where it shows up:** `xzregh/10A700_cpuid_query_and_unpack.c` (leaf values 0..10, 0xb, 0xd, 0xf, 0x80000002–0x80000004).
- **Why it matters:** These are well-defined CPUID leaves; an enum clarifies which pseudo-leaf helper is intended.
- **Reverse-engineering plan:** Add a `cpuid_leaf_t` enum with the observed values; rewrite the leaf comparisons to use named constants; refresh.
- **Status (2025-12-21):** Open – identified the leaf constants.

### RIP-relative ModRM signature constants
- **Where it shows up:** `xzregh/100D40_find_riprel_mov_or_lea.c`, `xzregh/100E00_find_riprel_mov.c`, `xzregh/100F60_find_riprel_lea.c`, `xzregh/101060_find_riprel_opcode_memref_ex.c`, `xzregh/102C60_find_riprel_mov_load_target_in_range.c`, `xzregh/103340_sshd_find_sensitive_data_base_via_krb5ccname.c` (mask checks against `0x5000000` and related patterns).
- **Why it matters:** These constants encode specific ModRM patterns (RIP-relative disp32); naming them avoids repeated magic masks across the opcode scanners.
- **Reverse-engineering plan:** Define a small enum or constant set for ModRM signature checks (e.g., `XZ_MODRM_RIPREL_DISP32`), then update the repeated `& 0xff00ff00 == 0x5000000` checks via locals rewrites; refresh.
- **Status (2025-12-21):** Open – repeated ModRM signature literal observed.

### Monitor payload source mode (cmd_type 3)
- **Where it shows up:** `xzregh/108270_sshd_monitor_cmd_dispatch.c` (`monitor_flags & 0xc0` with values 0x00/0x40/0x80/0xc0).
- **Why it matters:** The high bits select how cmd_type 3 sources payloads; a named enum clarifies the control flow and avoids ambiguous bit masks.
- **Reverse-engineering plan:** Add a small enum for the payload source mode (e.g., `monitor_payload_source_t`), then replace the bit-mask comparisons with named values; refresh.
- **Status (2025-12-21):** Open – identified the high-bit mode selector.

## Completed

- None yet.
