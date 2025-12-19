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
- Function documentation: `metadata/functions_autodoc.json` is the canonical store. Bootstrap it once with `scripts/build_autodoc_from_sources.py`; afterwards edit the JSON directly (Codex should update this file when refining names/descriptions). Do not hand-edit the derived files under `ghidra_scripts/generated/`. Entries can stay as raw strings for plate comments, or become objects with a `plate` string plus an `inline` array. Each inline entry should provide a `match` substring (and optional `occurrence`/`placement`), allowing the refresh pipeline to reinsert `// AutoDoc:` inline comments into `xzregh/*.c` without manual edits.
- Signatures and locals: `metadata/xzre_locals.json` holds the current mapping and gets copied into place during refresh runs so the project and text dumps stay in sync. Regenerate from the upstream sources with `scripts/extract_local_variables.py` when new functions land in `xzre/xzre_code/` (the extractor preserves any extra per-local override keys that aren’t emitted by Clang). When Ghidra invents unnamed register temps (e.g., `bVar*`), add them under the optional `register_temps` array so the post-processing step can rewrite their names/types in the exported C. The same block also handles awkward field overlays—set `"replacement"` to the literal C you want emitted (e.g., rewriting `local_70._40_4_` to `*(u32 *)&local_70.opcode_window[3]`) so you don’t have to mutate `xzregh/xzre_types.h`. For stack-resident structs that Ghidra split into multiple locals, locals entries may set `"stack_offset"` (e.g., `\"-0x40\"`) plus `"force_stack": true` to force the struct onto a specific stack slot and clear overlapping locals so the decompiler exports field accesses instead of the per-field variables.
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

### Third-Party Headers (OpenSSH/OpenSSL/XZ)
- We keep upstream headers under `third_party/include/` (separate from `xzregh/`) to improve type/signature fidelity without polluting the exported C.
- Use the helper to fetch a curated set of `.h` files for Feb 2024-era releases and discard the tarballs; it keeps only the relevant roots and their intra-package include dependencies:
  ```bash
  ./scripts/fetch_third_party_headers.py --dest third_party/include
  ```
  - OpenSSH portable 9.7p1 (`third_party/include/openssh`)
  - OpenSSL 3.0.13 (`third_party/include/openssl`)
  - XZ Utils 5.4.6 (`third_party/include/xz`)
- Adjust versions/URLs inside the script if you need a different snapshot, then rerun; it refreshes the header trees in place.
- The refresh pipeline already passes `third_party/include` into `ImportXzreTypes.py`; point any ad-hoc Ghidra signature passes or local analyses at that include root when applying prototypes/structs. Keep `xzre_types.json` as the curated source of truth—use the third-party headers as reference during RE, then copy only the needed defs/prototypes into the JSON once you confirm they match the binary, rather than wholesale replacing our pinned layouts.

## Working With Ghidra
- Refresh the project with the bundled helper (runs the import, replays header types/signatures, and exports the portable snapshot so the System V calling convention fix is always applied):
  ```bash
  ./scripts/refresh_xzre_project.sh
  ```
  - The script assumes Ghidra lives at `~/tools/ghidra_11.4.2_PUBLIC`. Override with `GHIDRA_HOME=/path/to/ghidra ./scripts/refresh_xzre_project.sh` if needed.
  - Function names get restored via `RenameFromLinkerMap.py` on every refresh before signatures are re-applied; if the renames are skipped, prototypes from `ApplySignaturesFromHeader.py` will no longer match the `.L`/`FUN_` symbols.
  - Each refresh now regenerates `ghidra_scripts/generated/xzre_locals.json` via `scripts/extract_local_variables.py` and post-runs `ApplyLocalsFromXzreSources.py`, which tries to push local variable names/types from `xzre/xzre_code` into the active program. When a function is absent from `liblzma_la-crc64-fast.o`, the script logs it as missing; this is expected until those routines (or matching symbol aliases) are imported.
- Use `./scripts/refresh_xzre_project.sh --check-only` to validate metadata changes without touching `ghidra_projects/` or `xzregh/`. It mirrors the full pipeline inside a temporary project, prints any AutoDoc diffs, and cleans up the sandbox when it exits. The refresh always ends with `scripts/postprocess_register_temps.py`, which reads the `register_temps` metadata and rewrites the exported `.c` files (renaming the Ghidra-only temps and forcing `BOOL` everywhere). Update the JSON first; the script makes the textual changes automatically.
- The refresh now also exports the obfuscated string blobs (`string_action_data`, `string_mask_data`) straight from `liblzma_la-crc64-fast.o` via `scripts/export_rodata_strings.py`. By default the dumps go to `/tmp/xzre_rodata`; if you override the output dir into the repo, the generated `.bin/.txt` files are ignored via `ghidra_scripts/generated/.gitignore`. A compact C view of the blobs plus de-obfuscation hints lives in `ghidra_scripts/generated/string_rodata.c`.
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

## Struct Reverse-Engineering Tracker
- Keep `docs/STRUCT_PROGRESS.md` up to date. It lists every struct exported in `metadata/xzre_types.json`, a running review count, and any notes so the next analyst can focus on the least-touched types first.
- Whenever you perform a meaningful pass on a struct (renaming fields, annotating behavior, documenting layout), increment its `Review Count` and summarize what changed in the `Notes` column.
- If new structs are added to the metadata, re-run the helper script or manually add a new row initialized with count `0` so it appears in the queue.
- A possible prompt: "Can you give meaningfull names for the possible unknowns and improve the other names if needed in the sshd_payload_ctx_t struct? You can look for the functions which use it in xzregh to find out. Can you also annotate where appropriate? Remember to make changes in the json, run the pipeline afterwards and check if changes are good. Don't forget to update STRUCT_PROGRESS.md"

## Next Steps for Analysts
- Review the imported program under `ghidra_projects/xzre_ghidra` and determine additional binaries or archives that should be brought into the workspace.
- Correlate findings with the sources in `xzre/` and document insights or triage queues in `PROGRESS.md`.

## Dynamic RE Tips
- Keys/payloads: the RSA hooks expect ChaCha-encrypted payloads signed with the attacker’s Ed448 private key. Only the public key is embedded (wrapped in `secret_data` and unwrapped by `secret_data_decrypt_with_embedded_seed`), so unsigned/invalid payloads fall back to the real OpenSSL path.
- Imports/globals: ensure libcrypto/libc imports resolve and `backdoor_hooks_data_blob` is initialised before driving hooks. In sandboxes, patch import pointers to real functions or preload stubs so the dispatcher doesn’t bail out.
- Payload state machine: `mm_answer_keyallowed_payload_dispatch_hook` enforces `payload_stream_validate_or_poison` and length checks. Feed well-formed chunks in order or temporarily NOP the state/exit paths if you need to observe deeper behavior without the hooks exiting early.
- Safety exits: monitor hooks call `exit()` and the dispatcher flips `disable_backdoor` on malformed inputs. For tracing, stub those exits or keep `do_orig` non-NULL in RSA hooks to prevent early bailouts.
- Priv-esc path: `sshd_monitor_cmd_dispatch` rewrites in-memory sshd flags (PermitRootLogin, PAM on/off, monitor IDs/sockets) and may call `setresuid/setresgid`/`system`. Test only against nonproduction sshd or stub those imports to avoid real privilege changes.

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
- Functions: `100020_x86_decode_instruction`, `100AC0_is_endbr32_or_64`, `100B10_find_endbr_prologue`, `100BA0_find_function_bounds`, `100C90_find_rel32_call_instruction`, `100D40_find_riprel_mov_or_lea`, `100E00_find_riprel_mov`, `100EB0_find_lea_with_displacement`, `100F60_find_riprel_lea`, `101020_find_string_lea_xref`, `101060_find_riprel_opcode_memref_ex`, `101120_find_riprel_ptr_lea_or_mov_load`, `101170_find_riprel_grp1_imm8_memref`, `102C60_find_riprel_mov_load_target_in_range`, `102A50_elf_find_function_ptr_slot`, `102D30_elf_build_string_xref_table`, `1032C0_elf_find_encoded_string_xref_site`, `10AC40_find_reg_to_reg_instruction`.

### ELF Introspection & Memory Utilities (`elf_mem`)
- Focus: parsing the ELF image, walking segments/relocations, and servicing allocator or TLS lookups needed before hooks fire.
- Functions: `101210_fake_lzma_free_noop`, `101240_elf_vaddr_range_has_pflags_impl`, `1013A0_elf_vaddr_range_has_pflags`, `1013B0_is_pt_gnu_relro`, `1013D0_elf_info_parse`, `101880_elf_gnu_hash_lookup_symbol`, `101B00_elf_gnu_hash_lookup_symbol_addr`, `101B30_memmove_overlap_safe`, `101B80_fake_lzma_alloc_resolve_symbol`, `101B90_elf_rela_find_relative_slot`, `101C30_elf_relr_find_relative_slot`, `101DC0_elf_find_import_reloc_slot`, `101E60_elf_find_plt_reloc_slot`, `101E90_elf_find_got_reloc_slot`, `101EC0_elf_get_text_segment`, `101F70_elf_get_rodata_segment_after_text`, `1020A0_elf_find_encoded_string_in_rodata`, `102150_elf_get_writable_tail_span`, `1022D0_elf_vaddr_range_in_relro_if_required`, `102370_is_range_mapped_via_pselect`, `102440_tls_get_addr_trampoline`, `102490_get_fake_lzma_allocator_blob`, `1024F0_get_elf_functions_table`, `103CE0_main_elf_resolve_stack_end_if_sshd`, `104030_init_cpuid_ifunc_entry_ctx`, `104060_get_fake_lzma_allocator`.

### SSHD Discovery & Sensitive Data Recon (`sshd_recon`)
- Focus: locating sshd entry points, enumerating monitor structures, and scoring sensitive-data handling paths including mm_* hooks.
- Functions: `102550_sshd_find_main_from_entry_stub`, `102FF0_sshd_find_monitor_field_slot_via_mm_request_send`, `103340_sshd_find_sensitive_data_base_via_krb5ccname`, `103680_sshd_find_sensitive_data_base_via_xcalloc`, `103870_sshd_score_sensitive_data_candidate_in_do_child`, `103910_sshd_score_sensitive_data_candidate_in_main`, `103990_sshd_score_sensitive_data_candidate_in_demote_sensitive_data`, `103D50_sshd_score_sensitive_data_candidate`, `103DB0_sshd_find_monitor_ptr_slot`, `105410_sshd_recon_bootstrap_sensitive_data`, `1039C0_argv_dash_option_contains_lowercase_d`, `103A20_sshd_validate_stack_argv_envp_layout`, `107400_sshd_log_via_sshlogv`, `107BC0_sshd_find_socket_fd_by_shutdown_probe`, `107C60_sshd_get_monitor_comm_fd`, `107D50_sshd_patch_permitrootlogin_usepam_and_hook_authpassword`, `107DE0_sshd_install_mm_log_handler_hook`, `107EA0_payload_stream_validate_or_poison`, `107F20_sshbuf_extract_rsa_modulus`, `108270_sshd_monitor_cmd_dispatch`, `108080_mm_answer_keyverify_send_staged_reply_hook`, `108100_mm_answer_authpassword_send_reply_hook`, `108EA0_mm_answer_keyallowed_payload_dispatch_hook`, `10A3A0_mm_log_handler_hide_auth_success_hook`, `108D50_payload_stream_decrypt_and_append_chunk`.

### Loader Hooks & Runtime Setup (`loader_rt`)
- Focus: initializing ld.so state, resolving libc/libcrypto imports, applying GOT/audit hooks, and staging the backdoor runtime before command execution.
- Functions: `102770_restore_ldso_audit_state`, `1027D0_hooks_ctx_init_or_wait_for_shared_globals`, `102850_init_backdoor_shared_globals`, `102890_libcrypto_imports_ready_or_install_bootstrap`, `102B10_sshd_validate_log_handler_slots`, `103F60_cache_cpuid_gotplt_slot_index`, `103F80_seed_got_ctx_for_tls_get_addr_parse`, `103FA0_resolve_gotplt_base_from_tls_get_addr`, `104010_cache_got_base_offset_from_cpuid_anchor`, `104080_find_link_map_l_name_offsets`, `104370_find_dl_naudit_slot`, `1045E0_resolve_libc_read_errno_imports`, `104660_scan_link_map_and_init_shared_libs`, `104A40_scan_shared_libraries_via_r_debug`, `104AE0_find_l_audit_any_plt_mask_and_slot`, `104EE0_find_l_audit_any_plt_mask_via_symbind_alt`, `1051E0_resolve_ldso_audit_offsets`, `105830_backdoor_install_runtime_hooks`, `106F30_cpuid_ifunc_stage2_install_hooks`, `107030_strlen_unbounded`, `107050_strnlen_bounded`, `107080_fd_read_full`, `1070F0_fd_write_full`, `107170_pointer_array_has_null`, `1074B0_count_null_terminated_ptrs`, `10A700_cpuid_gcc`, `10A720_cpuid_ifunc_resolver_entry`, `10A794_cpuid_ifunc_patch_got_for_stage2`, `10A800_get_cpuid_modified`, `backdoor_hooks_data_blob`.

### Crypto, Secret Data & Command Channel (`crypto_cmd`)
- Focus: cryptographic helpers, sshbuf serializers, secret-data staging, and the RSA/MM command hooks that enforce the backdoor policy.
- Functions: `103B80_dsa_pubkey_sha256_fingerprint`, `107190_chacha20_decrypt`, `1072B0_sha256_digest`, `107320_bignum_mpint_serialize`, `107510_rsa_pubkey_sha256_fingerprint`, `107630_verify_ed448_signed_payload`, `107A20_sshd_find_forged_modulus_sshbuf`, `107920_sshbuf_is_negative_mpint`, `107950_sshbuf_extract_ptr_and_len`, `1081D0_secret_data_decrypt_with_embedded_seed`, `1094A0_rsa_backdoor_command_dispatch`, `10A240_rsa_public_decrypt_backdoor_shim`, `10A2D0_evp_pkey_set1_rsa_backdoor_shim`, `10A330_rsa_get0_key_backdoor_shim`, `10A860_popcount_u64`, `10A880_encoded_string_id_lookup`, `10A990_secret_data_append_opcode_bit`, `10AA00_secret_data_append_code_bits`, `10AAC0_secret_data_append_singleton_bits`, `10AB70_secret_data_append_item_if_enabled`, `10AB90_secret_data_append_bits_from_addr_or_ret`, `10ABC0_secret_data_append_bits_from_call_site`, `10ABE0_secret_data_append_items_batch`.

## Ghidra Signature Quirks
- Headless imports flatten pointer qualifiers, so `const T *` becomes `T *` in `FunctionDefinitionDataType` prototypes even though the header retained `const`.
- Struct and enum tags collapse to their typedef names (e.g., `struct sshbuf *` renders as `sshbuf *`, `enum SocketMode` as `SocketMode`).
- Unsigned integer aliases and OpenSSH typedefs normalize to Ghidra builtins (`unsigned int`→`uint`, `unsigned char *`→`uchar *`).
- Function-pointer parameters become pointers to auto-generated typedefs (e.g., `BOOL (*appender)(...)` shows up as `appender *`).
- Treat these differences as cosmetic when diffing signatures; re-running `ApplySignaturesFromHeader.py` keeps behavioral parity even though the display strings differ.
