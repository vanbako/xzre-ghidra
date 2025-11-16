# Agent Onboarding – xzre Ghidra Project

## Project Purpose
- Centralize reverse-engineering artifacts for the `xzre` malware analysis effort.
- Maintain a headless Ghidra project (`xzre_ghidra`) sourced from the `liblzma_la-crc64-fast.o` object in `xzre/`.

## Key Locations
- `xzre/`: Original source, build scripts, and compiled objects from the xzre investigation; keep this upstream Git checkout untracked in this workspace (treat it as read-only and avoid staging it).
- `ghidra_projects/`: Workspace for Ghidra projects produced via headless runs.
  - `xzre_ghidra.gpr` / `xzre_ghidra.rep`: Ghidra project container and repository.
- `ghidra_projects/xzre_ghidra_portable.zip`: Exported archive containing the consumable project snapshot.
- `PROGRESS.md`: Rolling log for analysis milestones and outstanding follow-ups.

## Source of Truth for Reverse-Engineering Metadata
- Function documentation: `metadata/functions_autodoc.json` is the canonical store. Bootstrap it once with `scripts/build_autodoc_from_sources.py`; afterwards edit the JSON directly (Codex should update this file when refining names/descriptions). Do not hand-edit the derived files under `ghidra_scripts/generated/`.
- Signatures and locals: `metadata/xzre_locals.json` holds the current mapping and gets copied into place during refresh runs so the project and text dumps stay in sync. Regenerate from the upstream sources with `scripts/extract_local_variables.py` when new functions land in `xzre/xzre_code/`. When Ghidra invents unnamed register temps (e.g., `bVar*`), add them under the optional `register_temps` array so the post-processing step can rewrite their names/types in the exported C. The same block also handles awkward field overlays—set `"replacement"` to the literal C you want emitted (e.g., rewriting `local_70._40_4_` to `*(u32 *)&local_70.opcode_window[3]`) so you don’t have to mutate `xzregh/xzre_types.h`.
- If a metadata entry corresponds to a function that is not present in `liblzma_la-crc64-fast.o`, set `"skip_locals": true` for that entry. The extractor preserves this flag on rebuilds and the headless locals pass will silently ignore those functions until we import a binary that defines them.
- Refresh loop: `./scripts/refresh_xzre_project.sh` performs `metadata → Ghidra project → xzregh/`. It copies the JSON metadata into `ghidra_scripts/generated/`, applies it in a headless run, exports the project archive, and mirrors the updated comments back into `xzregh/*.c`. Any manual edits should hit the metadata JSON first, then re-run the refresh.
- Verification: the refresh emits `ghidra_scripts/generated/xzre_autodoc.json` as a derived artifact; differences between it and `metadata/functions_autodoc.json` indicate that the project mutated comments that were not recorded in metadata.
- Codex workflow:
  1. Review the decomp in `xzregh/`.
  2. Update `metadata/functions_autodoc.json` (and `metadata/xzre_locals.json` when renaming locals/parameters) with the improved insight.
  3. Run `./scripts/refresh_xzre_project.sh` to apply the metadata to Ghidra and regenerate the text dumps.

### Metadata Helpers & Notes
- `scripts/edit_autodoc.py <function>` opens your `$EDITOR` (or accepts `--set/--file/--stdin`) with the current entry so you can update `metadata/functions_autodoc.json` one function at a time without juggling the full JSON blob.
- `scripts/generate_function_stubs.py --batch <shortname>` writes `notes/<function>.md` scaffolds that capture the existing AutoDoc text, locals snapshot, and TODO checkboxes. Re-run with `--force` to refresh stubs or pass `--function <symbol>` for ad-hoc helpers.
- `scripts/check_locals_renames.py --output <report>` validates that every `register_temps` rename in `metadata/xzre_locals.json` actually shows up in the exported `xzregh/*.c`. `refresh_xzre_project.sh` runs it automatically and writes the results to `ghidra_scripts/generated/locals_rename_report.txt`; inspect that file whenever the refresh complains about lingering `local_*` names.
- Recommended loop: generate stubs for the batch you plan to tackle, jot raw observations in those Markdown files while reviewing `xzregh/`, then promote the distilled findings into the metadata JSON via the helper (and adjust `metadata/xzre_locals.json` for renamed locals/params). The stubs are scratchpads only—the JSON files remain the source of truth.

## Working With Ghidra
- Refresh the project with the bundled helper (runs the import, replays header types/signatures, and exports the portable snapshot so the System V calling convention fix is always applied):
  ```bash
  ./scripts/refresh_xzre_project.sh
  ```
  - The script assumes Ghidra lives at `~/tools/ghidra_11.4.2_PUBLIC`. Override with `GHIDRA_HOME=/path/to/ghidra ./scripts/refresh_xzre_project.sh` if needed.
  - Function names get restored via `RenameFromLinkerMap.py` on every refresh before signatures are re-applied; if the renames are skipped, prototypes from `ApplySignaturesFromHeader.py` will no longer match the `.L`/`FUN_` symbols.
  - Each refresh now regenerates `ghidra_scripts/generated/xzre_locals.json` via `scripts/extract_local_variables.py` and post-runs `ApplyLocalsFromXzreSources.py`, which tries to push local variable names/types from `xzre/xzre_code` into the active program. When a function is absent from `liblzma_la-crc64-fast.o`, the script logs it as missing; this is expected until those routines (or matching symbol aliases) are imported.
- Use `./scripts/refresh_xzre_project.sh --check-only` to validate metadata changes without touching `ghidra_projects/` or `xzregh/`. It mirrors the full pipeline inside a temporary project, prints any AutoDoc diffs, and cleans up the sandbox when it exits. The refresh always ends with `scripts/postprocess_register_temps.py`, which reads the `register_temps` metadata and rewrites the exported `.c` files (renaming the Ghidra-only temps and forcing `BOOL` everywhere). Update the JSON first; the script makes the textual changes automatically.
- Produce a portable archive suitable for sharing or version control without committing the working `.rep` directory:
  ```bash
  ~/tools/ghidra_11.4.2_PUBLIC/support/analyzeHeadless ghidra_projects xzre_ghidra \
    -process liblzma_la-crc64-fast.o \
    -noanalysis \
    -scriptPath ghidra_scripts \
    -postScript ExportProjectArchive.py archive=ghidra_projects/xzre_ghidra_portable.zip
  ```
  - The custom `ExportProjectArchive.py` script zips the `.gpr` file and entire `.rep` directory into `xzre_ghidra_portable.zip`, keeping the repo clean while preserving a reproducible snapshot.
- Use `PROGRESS.md` to log any specialized scripts, exports, or follow-up tasks created during analysis.

## Updating the Progress Log
- Append a new entry at the top of `PROGRESS.md` after each session.
- Capture the date (`YYYY-MM-DD`), the action taken, the rationale, and the next intended step.
- Include links to generated reports or scripts when relevant so the next analyst can find them quickly.

## Next Steps for Analysts
- Review the imported program under `ghidra_projects/xzre_ghidra` and determine additional binaries or archives that should be brought into the workspace.
- Correlate findings with the sources in `xzre/` and document insights or triage queues in `PROGRESS.md`.

## Quick Batch Handles
When you are ready for more reversing you can simply ask, e.g., “Can you do an RE session of batch `opco_patt`?” and Codex will fan out the right stubs/scripts. The short names are:
- `opco_patt` – Opcode scanners & pattern utilities.
- `elf_mem` – ELF introspection and allocator helpers.
- `sshd_recon` – SSHD discovery and sensitive data scoring.
- `loader_rt` – Loader hooks and runtime setup.
- `crypto_cmd` – Crypto helpers, secret-data staging, and RSA/MM hooks.

## Function Work Batches
To keep Codex tasks within a manageable context window, the 126 exported functions are grouped into five dependency-oriented batches. Reference the group name when requesting follow-on work.

### Opcode Scanners & Pattern Utilities (`opco_patt`)
- Focus: x86 disassembly helpers and instruction/operand searchers used by higher-level recon routines.
- Functions: `100020_x86_dasm`, `100AC0_is_endbr64_instruction`, `100B10_find_function_prologue`, `100BA0_find_function`, `100C90_find_call_instruction`, `100D40_find_mov_lea_instruction`, `100E00_find_mov_instruction`, `100EB0_find_lea_instruction`, `100F60_find_lea_instruction_with_mem_operand`, `101020_find_string_reference`, `101060_find_instruction_with_mem_operand_ex`, `101120_find_instruction_with_mem_operand`, `101170_find_add_instruction_with_mem_operand`, `102C60_find_addr_referenced_in_mov_instruction`, `102A50_elf_find_function_pointer`, `102D30_elf_find_string_references`, `1032C0_elf_find_string_reference`, `10AC40_find_reg2reg_instruction`.

### ELF Introspection & Memory Utilities (`elf_mem`)
- Focus: parsing the ELF image, walking segments/relocations, and servicing allocator or TLS lookups needed before hooks fire.
- Functions: `101210_fake_lzma_free`, `101240_elf_contains_vaddr_impl`, `1013A0_elf_contains_vaddr`, `1013B0_is_gnu_relro`, `1013D0_elf_parse`, `101880_elf_symbol_get`, `101B00_elf_symbol_get_addr`, `101B30_c_memmove`, `101B80_fake_lzma_alloc`, `101B90_elf_find_rela_reloc`, `101C30_elf_find_relr_reloc`, `101DC0_elf_get_reloc_symbol`, `101E60_elf_get_plt_symbol`, `101E90_elf_get_got_symbol`, `101EC0_elf_get_code_segment`, `101F70_elf_get_rodata_segment`, `1020A0_elf_find_string`, `102150_elf_get_data_segment`, `1022D0_elf_contains_vaddr_relro`, `102370_is_range_mapped`, `102440_j_tls_get_addr`, `102490_get_lzma_allocator_address`, `1024F0_get_elf_functions_address`, `103CE0_main_elf_parse`, `104030_init_elf_entry_ctx`, `104060_get_lzma_allocator`, `10D000_lzma_check_init`, `10D008_tls_get_addr`, `10D010_lzma_free`, `10D018_lzma_alloc`.

### SSHD Discovery & Sensitive Data Recon (`sshd_recon`)
- Focus: locating sshd entry points, enumerating monitor structures, and scoring sensitive-data handling paths including mm_* hooks.
- Functions: `102550_sshd_find_main`, `102FF0_sshd_find_monitor_field_addr_in_function`, `103340_sshd_get_sensitive_data_address_via_krb5ccname`, `103680_sshd_get_sensitive_data_address_via_xcalloc`, `103870_sshd_get_sensitive_data_score_in_do_child`, `103910_sshd_get_sensitive_data_score_in_main`, `103990_sshd_get_sensitive_data_score_in_demote_sensitive_data`, `103D50_sshd_get_sensitive_data_score`, `103DB0_sshd_find_monitor_struct`, `105410_sshd_find_sensitive_data`, `1039C0_check_argument`, `103A20_process_is_sshd`, `107400_sshd_log`, `107BC0_sshd_get_usable_socket`, `107C60_sshd_get_client_socket`, `107D50_sshd_patch_variables`, `107DE0_sshd_configure_log_hook`, `107EA0_check_backdoor_state`, `107F20_extract_payload_message`, `108270_sshd_proxy_elevate`, `108080_mm_answer_keyverify_hook`, `108100_mm_answer_authpassword_hook`, `108EA0_mm_answer_keyallowed_hook`, `10A3A0_mm_log_handler_hook`, `108D50_decrypt_payload_message`.

### Loader Hooks & Runtime Setup (`loader_rt`)
- Focus: initializing ld.so state, resolving libc/libcrypto imports, applying GOT/audit hooks, and staging the backdoor runtime before command execution.
- Functions: `102770_init_ldso_ctx`, `1027D0_init_hooks_ctx`, `102850_init_shared_globals`, `102890_init_imported_funcs`, `102B10_validate_log_handler_pointers`, `103F60_update_cpuid_got_index`, `103F80_get_tls_get_addr_random_symbol_got_offset`, `103FA0_update_got_address`, `104010_update_got_offset`, `104080_find_link_map_l_name`, `104370_find_dl_naudit`, `1045E0_resolve_libc_imports`, `104660_process_shared_libraries_map`, `104A40_process_shared_libraries`, `104AE0_find_link_map_l_audit_any_plt_bitmask`, `104EE0_find_link_map_l_audit_any_plt`, `1051E0_find_dl_audit_offsets`, `105830_backdoor_setup`, `106F30_backdoor_init_stage2`, `107030_c_strlen`, `107050_c_strnlen`, `107080_fd_read`, `1070F0_fd_write`, `107170_contains_null_pointers`, `1074B0_count_pointers`, `10A700_cpuid_gcc`, `10A720_backdoor_entry`, `10A794_backdoor_init`, `10A800_get_cpuid_modified`, `xzre_globals`.

### Crypto, Secret Data & Command Channel (`crypto_cmd`)
- Focus: cryptographic helpers, sshbuf serializers, secret-data staging, and the RSA/MM command hooks that enforce the backdoor policy.
- Functions: `103B80_dsa_key_hash`, `107190_chacha_decrypt`, `1072B0_sha256`, `107320_bignum_serialize`, `107510_rsa_key_hash`, `107630_verify_signature`, `107A20_sshd_get_sshbuf`, `107920_sshbuf_bignum_is_negative`, `107950_sshbuf_extract`, `1081D0_secret_data_get_decrypted`, `1094A0_run_backdoor_commands`, `10A240_hook_RSA_public_decrypt`, `10A2D0_hook_EVP_PKEY_set1_RSA`, `10A330_hook_RSA_get0_key`, `10A860_count_bits`, `10A880_get_string_id`, `10A990_secret_data_append_from_instruction`, `10AA00_secret_data_append_from_code`, `10AAC0_secret_data_append_singleton`, `10AB70_secret_data_append_item`, `10AB90_secret_data_append_from_address`, `10ABC0_secret_data_append_from_call_site`, `10ABE0_secret_data_append_items`.

## Ghidra Signature Quirks
- Headless imports flatten pointer qualifiers, so `const T *` becomes `T *` in `FunctionDefinitionDataType` prototypes even though the header retained `const`.
- Struct and enum tags collapse to their typedef names (e.g., `struct sshbuf *` renders as `sshbuf *`, `enum SocketMode` as `SocketMode`).
- Unsigned integer aliases and OpenSSH typedefs normalize to Ghidra builtins (`unsigned int`→`uint`, `unsigned char *`→`uchar *`).
- Function-pointer parameters become pointers to auto-generated typedefs (e.g., `BOOL (*appender)(...)` shows up as `appender *`).
- Treat these differences as cosmetic when diffing signatures; re-running `ApplySignaturesFromHeader.py` keeps behavioral parity even though the display strings differ.
