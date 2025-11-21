# Progress Log

Document notable steps taken while building out the Ghidra analysis environment for the xzre artifacts. Add new entries in reverse chronological order and include enough context so another analyst can pick up where you left off.

## 2025-11-21
- `cmd_arguments_t`: renamed the anonymous flag bytes to `control_flags`/`monitor_flags`/`request_flags`, documented each bit’s role (log-hook install, PAM disablement, explicit socket selection, payload sourcing/continuations), spelled out how `payload_hint` doubles as a continuation length vs. sshd_offsets overlay, and reran `./scripts/refresh_xzre_project.sh` so `xzre_types.h`/`xzregh/*` reflect the new names. STRUCT_PROGRESS updated for review #1.
- Next: tighten the `CommandFlags*` enums (they still describe the old bit meanings) and reconcile the AutoDoc delta the refresh keeps reporting for `xzre_globals`.

## 2025-11-20
- `sshd_log_ctx_t`: renamed the squelch/syslog flags, typed the handler/ctx slot pointers, and documented the sshlogv + log-fragment anchors used by the mm_log_handler hook; reran `./scripts/refresh_xzre_project.sh` so xzre_types.h/xzregh/portable snapshot match the metadata and updated STRUCT_PROGRESS for review #1.
- Next: either re-express the libc_imports copy in backdoor_setup to avoid the negative-offset hack or sync the AutoDoc delta the refresh keeps flagging.

## 2025-11-20
- `sshd_ctx_t`: renamed the hook entry fields, dispatch slots, and staged payload buffers (keyverify reply + pending authpassword body), documented the EncodedStringId 0x198 auth-log probe plus the PAM/root globals, and reran `./scripts/refresh_xzre_project.sh` so xzre_types.h/xzregh/portable archive all reflect the updated layout. Updated STRUCT_PROGRESS for review #1.
- Next: if we can identify the actual string behind EncodedStringId 0x198, propagate that label into the enum/field comment; also worth syncing the AutoDoc delta flagged by the refresh when time allows.

## 2025-11-20
- Added a refresh step that exports the obfuscated string blobs straight from `liblzma_la-crc64-fast.o` (`string_action_data` / `string_mask_data`) via `scripts/export_rodata_strings.py`; the pipeline now emits binary dumps plus commented hexdumps and a best-effort decoded table (`ghidra_scripts/generated/{string_action_data,string_mask_data}.txt/bin`, `encoded_string_ids.txt`, `string_rodata_summary.txt`). Documented the new outputs in AGENTS.md.
- Next: if more precise plaintext is needed, refine the decoder heuristic in `export_rodata_strings.py` or wire up a full deobfuscation using the trie/mask data instead of enum-name hints.

## 2025-11-20
- `global_context_t`: renamed the ambiguous fields (string anchors, monitor slot, code/data bounds, payload buffer/state, secret-data flags) and annotated each member so callers know how the imports, sshd metadata, streaming buffers, and attestation bookkeeping fit together. Ran `./scripts/refresh_xzre_project.sh` so the new names propagate into xzregh and the portable archive. STRUCT_PROGRESS bumped for review #1.
- Next: if we want the AutoDoc warning cleared, diff `ghidra_scripts/generated/xzre_autodoc.json` against `metadata/functions_autodoc.json` and sync the remaining comment delta.

## 2025-11-20
- `elf_handles_t`: renamed the handles to `sshd`/`ldso`/`libc`/`liblzma`/`libcrypto`, added inline comments explaining what each descriptor feeds (r_debug head, audit hooks, allocator glue, hook blob, RSA/EVP trampolines), and reran `./scripts/refresh_xzre_project.sh` so the updated names propagate through xzregh and the portable archive. Updated STRUCT_PROGRESS for review #1.
- Next: consider aligning nearby wrappers (`main_elf_t`, backdoor data consumers) if any helper conventions still mention the old handle names; refresh reported an AutoDoc mismatch vs metadata, so review `ghidra_scripts/generated/xzre_autodoc.json` when convenient.

## 2025-11-20
- `got_ctx_t`: reworked the GOT patch context to name the __tls_get_addr anchor and cpuid slot bookkeeping (`tls_got_entry`, `cpuid_got_slot`, `cpuid_slot_index`, `got_base_offset`), refreshed the type docs/AutoDocs to explain how `cpuid_random_symbol_addr` reconstructs the GOT base, and ran `./scripts/refresh_xzre_project.sh` so xzregh/xzre_types.h and the portable archive show the new layout. Updated STRUCT_PROGRESS for review #1.
- Next: continue tightening the loader relocation structs (e.g., `global_context_t` or the remaining GOT helpers) now that the GOT anchor/slot naming is settled.

## 2025-11-19
- `backdoor_setup_params_t`: finished the stage-two payload structs by renaming the padding/ptr fields (`bootstrap_padding`, `shared_globals`, `hook_ctx`) and documenting how the dummy `lzma_check_state` + `elf_entry_ctx_t` are used during `backdoor_setup`. Ran `./scripts/refresh_xzre_project.sh` (user confirmed) so the exported headers/project picked up the annotations, then updated STRUCT_PROGRESS.
- Next: move on to `backdoor_data_handle_t` or the remaining loader structs now that the setup argument bundle is clarified.

## 2025-11-19
- `key_payload_t`: completed the payload chain by annotating the streaming frame—renamed the raw ChaCha ciphertext buffer, length field, and body view, documented how decrypt_payload_message consumes the plaintext header/length, and refreshed the project so the exported headers and Ghidra snapshot now show the improved layout. STRUCT_PROGRESS updated for review #1.
- Next: move down the struct queue (e.g., `backdoor_setup_params_t` or `backdoor_data_handle_t`) now that the payload family is fully documented.

## 2025-11-19
- `backdoor_payload_t`: clarified the union that wraps the decrypted payload by renaming the flat buffer to `raw`, annotating the embedded header/body view, and explaining how the RSA hooks use the raw bytes for hashing versus the structured fields for parsing. Ran `./scripts/refresh_xzre_project.sh` so the regenerated headers and Ghidra project expose the new comments, then bumped STRUCT_PROGRESS for review #1.
- Next: finish the payload chain by documenting `key_payload_t` (streaming frame with length prefix) before tackling the remaining backdoor structs.

## 2025-11-19
- `backdoor_payload_body_t`: renamed the Ed448/signature/args/body fields to `ed448_signature`, `cmd_flags`, and `monitor_payload`, added inline comments that capture the signature coverage plus the 0x87 payload offset, and ran `./scripts/refresh_xzre_project.sh` so `xzregh/xzre_types.h` and the Ghidra project now show the annotated layout. Updated STRUCT_PROGRESS for review #1.
- Next: continue documenting the rest of the payload chain (`backdoor_payload_t` → `key_payload_t`) so every layer of the RSA transport is described before moving on to the remaining backdoor structs.

## 2025-11-19
- `backdoor_hooks_ctx_t`: renamed the scratch/pointer fields (`bootstrap_scratch`, `hooks_data_slot_ptr`, `symbind64_trampoline`, `rsa_*_entry`, `mm_*_entry`) and clarified that the remaining pointer slots are placeholders for future log/monitor contexts. Ran the refresh pipeline so `init_hooks_ctx`/`backdoor_setup` now refer to the updated names and updated STRUCT_PROGRESS.
- Next: keep marching down the backdoor struct list (`backdoor_payload_body_t` still pending) so all of the payload plumbing is equally well documented.

## 2025-11-19
- `backdoor_payload_hdr_t`: replaced the anonymous field_a/b/c triplet with the stride/index/bias naming, documented how run_backdoor_commands collapses them into `cmd_type` and how decrypt_payload_message reuses the 16 bytes as the ChaCha IV, and refreshed the project so the updated comments propagate into `xzregh`/Ghidra. Struct tracker bumped to reflect the pass.
- Next: continue down the payload record chain by documenting `backdoor_payload_body_t` so the decrypted args/signature/body layout is just as clear.

## 2025-11-19
- Documented `backdoor_hooks_data_t`: annotated each sub-structure (`ldso_ctx`, `global_ctx`, import/sshd/log blocks) and described the signed payload tail so the liblzma blob is self-explanatory in both metadata and the exported headers; refreshed the project so every hook consumer sees the new comments.
- Next: continue down the review order with `backdoor_hooks_ctx_t` to untangle the per-hook callback pointers.

## 2025-11-19
- Clarified `backdoor_shared_libraries_data_t`: renamed the PLT slot pointers (`rsa_public_decrypt_slot`, `evp_set1_rsa_slot`, `rsa_get0_key_slot`), the hook blob pointer (`hooks_data_slot`), and the aggregate map pointer (`shared_maps`), added inline comments, and refreshed the project so `process_shared_libraries[_map]` and `backdoor_setup` now show the tighter naming.
- Next: dig into `backdoor_hooks_data_t` (review order #3) so the liblzma-resident blob is equally well documented.

## 2025-11-19
- Renamed `backdoor_shared_globals_t` members to spell out their roles (mm hook jump, EVP trampoline, global ctx slot), annotated each field in `metadata/xzre_types.json`, and refreshed the project so the decomp (`backdoor_setup`, `init_shared_globals`, `backdoor_init_stage2`) now references the clearer names.
- Next: move to `backdoor_shared_libraries_data_t` (review order #2) so the loader snapshot gets the same treatment.

## 2025-11-19
- Renamed the opaque `dasm_ctx_t` slots (`imm64_reg`, `operand*`, `insn_offset`, etc.) to descriptive names, annotated every field in `metadata/xzre_types.json`, and ran `./scripts/refresh_xzre_project.sh` so the header plus all MOV/LEA/CALL scanners now describe and use the updated members.
- Next: continue documenting decoder-adjacent structs (e.g., the `string_references_t` scaffolding) so cross-referencing helpers rely on typed fields instead of ad-hoc offsets.

## 2025-11-18
- Added inline comments for every field in `imported_funcs_t`, explaining which slots hold the preserved libcrypto entry points, which track the PLT jumps, and how the crypto/helper stubs (BN/EVP/ChaCha) are used by the payload pipeline. The struct now mirrors the level of documentation we have on `elf_info_t`/`libc_imports_t`.
- Ran `./scripts/refresh_xzre_project.sh` so the annotations propagated into `xzregh/xzre_types.h` and the Ghidra project.
- Next: continue annotating the remaining structs in `docs/STRUCT_PROGRESS.md` (starting with the zero-count entries) to keep the metadata self-documenting.

## 2025-11-18
- Annotated every field in `elf_info_t` and `libc_imports_t`, capturing what each pointer/flag represents (PT_DYNAMIC tables, segment caches, GNU hash metadata, libc trampolines, etc.) so future reversing sessions can reason about the data without re-reading the importers.
- Regenerated the headless project via `./scripts/refresh_xzre_project.sh` so the inline comments propagate into `xzregh/xzre_types.h` and the Ghidra project.
- Next: continue working through the remaining structs with review count `0` (see `docs/STRUCT_PROGRESS.md`) and add similar inline annotations as they are understood.

## 2025-11-18
- Added `docs/STRUCT_PROGRESS.md`, auto-populated it with every struct from `metadata/xzre_types.json`, and seeded the review counts/notes for the structs we have already annotated (`elf_info_t`, `libc_imports_t`, `imported_funcs_t`, `sshd_payload_ctx_t`). Future analysts can bump the counts and add notes as they work through the lower-priority entries.
- Documented the struct-tracking workflow in `AGENTS.md` so each session knows to update the progress file whenever a struct is revisited or a new one is added.
- Next: continue tackling the structs with a review count of `0` and update the tracker after each pass so prioritization stays obvious.

## 2025-11-18
- opco_patt locals sweep: typed the scratch decoder contexts in the MOV/LEA/CALL/string finders as `dasm_ctx_t`, renamed the range/xref iterators inside `elf_find_string_references`, and made the string-entry offsets unsigned so the decomp reflects the underlying tables.
- Ran `./scripts/refresh_xzre_project.sh`; locals rename report is clean and `xzregh/102D30_elf_find_string_references.c` picked up the new naming.
- Continued unwinding `elf_find_string_references`: forced the code segment bounds and target calculations to use plain `u8 *` math instead of the decoder-struct offsets and normalized the return path to a simple TRUE.
- Next: carry the `u8 *`-based code/target math into metadata so future refreshes keep the simplified pointers without reintroducing the decoder offsets.

## 2025-11-18
- Added `scripts/fetch_third_party_headers.py` to pull Feb 2024-era headers (OpenSSH 9.7p1, OpenSSL 3.0.13, XZ Utils 5.4.6) into `third_party/include/` while discarding the tarballs; refreshed `AGENTS.md` with usage notes so analysts can re-run or bump versions as needed.
- Ran the helper to stage headers under `third_party/include/{openssh,openssl,xz}` and trimmed them to the relevant roots plus transitive includes.
- Wired the refresh pipeline to pass `third_party/include` into `ImportXzreTypes.py` so signature application sees upstream structs/prototypes.
- Next: if new upstream snapshots are needed, tweak the script versions/urls and rerun before the next refresh.

## 2025-11-18
- elf_mem follow-up: exposed the recursion-depth arg in `elf_contains_vaddr_impl` (now named `depth_param`) and added locals metadata for the trap stubs (`lzma_check_init`, `tls_get_addr`, `lzma_free`, `lzma_alloc`) so their placeholders stay tracked in metadata.
- Ran `./scripts/refresh_xzre_project.sh`; rename report is clean and the exported `xzregh` picks up the depth rename.
- Next: if we pull in more ELF sources, consider wiring a seed value for `depth_param` to avoid the implicit zeroing Ghidra assumes here.

## 2025-11-18
- elf_mem sweep: retyped the RELA/RELR range limits to `u8 *`, renamed the probe page for `is_range_mapped`, and made the code/data/rodata segment cursors explicitly `u64`/`u8 *` (added the missing rodata `phdr_index` and swapped the data-segment span to an unsigned size).
- Ran `./scripts/refresh_xzre_project.sh`; `ghidra_scripts/generated/locals_rename_report.txt` is clean and the exported `xzregh` shows the clarified bounds/page/segment names.
- Next: consider exposing the recursion-depth arg in `elf_contains_vaddr_impl` or adding metadata for the trap stubs if we need to annotate their placeholders later.

## 2025-11-18
- Loader_rt sweep: named the ld.so string/size/ctx temps in `find_dl_naudit` and expanded the disassembler field rewrites in `find_link_map_l_audit_any_plt_bitmask` so the decomp drops the raw `_0_4_`/`_40_4_` accesses. Ran `./scripts/refresh_xzre_project.sh`; locals rename report is clean and the exported `xzregh` now shows the clarified names.
- Next: consider tackling the remaining large scratch structs in `backdoor_setup` if more anonymous `local_*` temps surface in future imports.

## 2025-11-18
- Extended the `sshd_recon` locals sweep to `mm_answer_keyallowed_hook`: mapped command type/state, libc/sshd ctx handles, payload lengths/offsets, keyverify/authpayload cursors, and the sock-read merge scratch so the exported C reads cleanly.
- Revisited the monitor struct finder and named its vote counters/cursors and the secret-data append flag; refreshed the headless project and the locals rename report stayed clean.
- Next: keep walking the monitor/payload hooks for any remaining anonymous temps as we import additional sshd binaries.

## 2025-11-18
- Passed over the `sshd_recon` helpers again to tighten locals/register temps: the scoring helpers now expose `score`/`base_hit`/`offset*`/`demote_hit` cursors, `extract_payload_message` names the search offset, match window, big-endian length cursors, and modulus field pointers, and the authpassword hook labels the reply buffer/length scratch space. Updated `metadata/xzre_locals.json` accordingly.
- Ran `./scripts/refresh_xzre_project.sh`; the regenerated `xzregh` sources picked up the new names and `ghidra_scripts/generated/locals_rename_report.txt` reports a clean pass.
- Next: extend the same treatment to `mm_answer_keyallowed_hook` and revisit the monitor struct finders if any residual `local_*` temps show up in the next decomp export.

## 2025-11-17
- Revisited the opco_patt AutoDocs with the improved sources and dependencies in mind: clarified decoder behavior, ModRM/REX/DF2 requirements, address recomputation paths, and how the string/reloc walkers tighten function bounds. Updated the relevant entries in `metadata/functions_autodoc.json` and pushed them through the headless refresh.
- Ran `./scripts/refresh_xzre_project.sh`; exported comments now mirror the richer descriptions and the locals rename report remains clean.
- Next: consider a second pass over the CET prologue scans once more binaries are imported to ensure the ENDBR alignment rules still hold.

## 2025-11-17
- Reworked the opco_patt AutoDoc copy in `metadata/functions_autodoc.json` to spell out the decoder behavior, opcode/ModRM requirements, and address calculations across `x86_dasm`, the MOV/LEA/MOV+ADD scanners, string-xref helpers, reloc-backed pointer finder, and reg2reg matcher.
- Ran `./scripts/refresh_xzre_project.sh`; the exported `xzregh/` comments now match the refreshed wording and the locals rename report remains clean.
- Next: revisit whether `find_function`/`find_function_prologue` need more nuance around CET vs legacy ranges once we analyse additional binaries.

## 2025-11-17
- Tightened the `opco_patt` locals by mapping the decoder/pattern-scan register temps (`x86_dasm`, the `find_*` MOV/LEA/CALL helpers, string xref builders) to accurate pointer/BOOL types; added fresh metadata entries for `elf_find_function_pointer`, `find_instruction_with_mem_operand`, and `find_reg2reg_instruction`.
- Ran `./scripts/refresh_xzre_project.sh`; the headless pass and locals rename report came back clean, and `xzregh/` now reflects the renamed cursors/targets/contexts across the opcode scanners and string walkers.
- Next: revisit the `elf_find_string_references` pointer math to see if we can drop the residual casts once the code/size bookkeeping is clearer.

## 2025-11-17
- Reworked the `crypto_cmd` batch metadata: added missing entries for `dsa_key_hash`,
  the sshbuf helpers, secret-data appender wrappers, and the RSA hook shims, then
  mapped the high-traffic temporaries (imports, serialized lengths, cursor copies,
  etc.) via `register_temps` so the exported C names reflect their purpose.
- Focused on the crypto paths (`bignum_serialize`, `verify_signature`, ChaCha/SHA
  helpers, `sshd_get_sshbuf`, the sshbuf extractors, and the secret-data sweepers)
  to annotate the pointer temps and offsets, bringing the metadata in sync with the
  reversing notes.
- Ran `./scripts/refresh_xzre_project.sh` to push the JSON into the headless Ghidra
  project and regenerate `xzregh/*.c`/`ghidra_projects/xzre_ghidra_portable.zip`; the
  generated `ghidra_scripts/generated/locals_rename_report.txt` reports clean rewrites.
- Next: continue tightening the rsa/dsa helper structs in `run_backdoor_commands`
  once we’re ready to rename the nested `cmd_arguments_t` overlays.

## 2025-11-17
- Revisited every `loader_rt` export and mapped the remaining `p?Var*`/`local_*`
  temporaries in `metadata/xzre_locals.json`, covering the ld.so setup helpers,
  libc import resolvers, GOT/AUDIT scanners, cpuid stubs, and the file-descriptor
  shims. Added the missing metadata for the `_cpuid_gcc`/`_get_cpuid_modified`
  pair and taught `scripts/postprocess_register_temps.py` how to locate files
  whose short names drop a leading underscore so the cpuid sources pick up the
  new names.
- Ran `./scripts/refresh_xzre_project.sh` followed by a manual
  `python scripts/postprocess_register_temps.py --metadata metadata/xzre_locals.json --xzregh-dir xzregh`
  to push the refreshed metadata through headless Ghidra, regenerate `xzregh/*.c`,
  and update the portable project archive. The locals rename report is clean,
  and the refresher only emitted the usual register-temp warnings for the sshd
  helpers.
- Next: continue peeling local/register-temp coverage into `backdoor_setup` and
  the remaining loader structures so their large scratch structs get the same
  treatment on the next metadata pass.

## 2025-11-15
- Revisited the `opco_patt` helpers and added explicit register-temp metadata so
  all of the remaining `local_*` decoder scratch variables have descriptive
  names (`opcode_class_masks`, `scratch_ctx`, `scanner_ctx`, etc.). Updated
  `metadata/xzre_locals.json` for the instruction scanners, string xref
  builders, and pointer-finder helpers, then ran
  `./scripts/refresh_xzre_project.sh` to regenerate the exported sources and
  portable Ghidra project with the refreshed metadata.
- Next: continue expanding the metadata coverage for the remaining pointer
  utilities (e.g., `find_reg2reg_instruction`) if we discover additional
  scratch locals that could benefit from stronger typing.

## 2025-11-15
- Tagged the remaining `sshd_recon` locals inside `metadata/xzre_locals.json`
  (extra disassembly contexts, store-slot scratch buffers, monitor vote table,
  sshd_main/code-scan bounds, etc.) so the headless run can replace the last
  `local_*` identifiers in `sshd_find_main`, the xcalloc/KRB5 heuristics,
  `sshd_find_monitor_struct`, and `sshd_find_sensitive_data` with meaningful
  names/types.
- Ran `./scripts/refresh_xzre_project.sh` to push the metadata through Ghidra,
  regenerate `xzregh/*.c`, and refresh the portable project archive with the
  updated locals mapping.
- Next: audit the regenerated sources to see if any sshd recon helper still
  exports autogenerated locals; if so, capture their structure in the JSON and
  rerun the refresh.

## 2025-11-15
- Added register-temp mappings for the sshd monitor/payload helpers (`sshd_log`,
  `sshd_proxy_elevate`, `mm_answer_keyallowed_hook`, `mm_log_handler_hook`) so
  the next refresh renames every lingering `local_*` scratch buffer and the
  propagated `p?Var*` temporaries to descriptive names (e.g., RSA digest
  buffers, monitor request payloads, log rewrite fragments). Ran
  `./scripts/refresh_xzre_project.sh --check-only` to verify the metadata parses
  cleanly; the full refresh can wait until we’re ready to push these names into
  `xzregh/` and the portable project snapshot.
- Next: execute the full refresh (no `--check-only`) once we’re done staging the
  rest of the locals so the exported C picks up the new identifiers.

## 2025-11-15
- Reflowed every `sshd_recon` AutoDoc entry in `metadata/functions_autodoc.json` to multi-line form (120-char wraps) so
  the generated comments in `xzregh/*.c` are readable again. No refresh yet—the check-only run still reflects the
  same metadata contents.
- Next: once the locals metadata is tidied, run the full refresh to push both the wording updates and the new wrapping
  through Ghidra/xzregh.

## 2025-11-15
- Completed the `sshd_recon` RE batch: generated fresh stubs, reread the sshd discovery/sensitive-data helpers plus the monitor/MM hooks, and rewrote all 25 corresponding entries in `metadata/functions_autodoc.json` so their narratives now capture the real heuristics (monitor field voting, payload state gating, socket reuse, PAM/log toggles, etc.).
- Ran `./scripts/refresh_xzre_project.sh --check-only` to validate the new metadata, confirm no derived artifacts drifted, and keep the portable project untouched until we’re ready for a full refresh.
- Next: extend `metadata/xzre_locals.json` for any lingering sshd monitor/payload helpers that still export `local_*` temps before running the full refresh that updates `ghidra_projects/` and `xzregh/*.c`.

## 2025-11-15
- Captured the telemetry/cursor semantics from the `elf_mem` RE pass: updated `metadata/functions_autodoc.json` so `elf_get_reloc_symbol`, `elf_get_code_segment`, `elf_get_rodata_segment`, and `elf_find_string` now document the `secret_data_*` gates, and taught `metadata/xzre_locals.json` to rename the RELA/RELR resume pointers plus range bounds.
- Skipped `./scripts/refresh_xzre_project.sh` this round; follow-up run needed once we’re ready to push the metadata back into Ghidra and the exported sources.
- Next: kick off a refresh (at least `--check-only`) to confirm the renamed register temps stick inside `xzregh/101B90*.c` and `101C30*.c`, then decide if any additional `elf_mem` helpers need similar instrumentation notes.

## 2025-11-15
- Ran an `elf_mem` RE session: generated the batch stubs, reread the allocator shims, ELF walkers, relocation scanners, segment finders, and TLS/lzma trap stubs under `xzregh/1012*–10D01*`, and populated each `notes/*.md` scratchpad with concrete observations (recursion guard limits, RELR decoding, secret-data telemetry gates, etc.) so the next analyst can jump directly to the nuanced behaviour.
- Verified the existing AutoDoc/locals metadata already reflect the observed behaviour, so no JSON edits or refresh run were required this round.
- Next: hook these notes back into the canonical metadata if we decide to capture the telemetry instrumentation or rename the RELA/RELR cursor parameters so future refreshes can apply the richer nomenclature.

## 2025-11-15
- Corrected the `opco_patt` AutoDoc updates: the JSON keys had been written with `0xADDR_name` prefixes, so the refresh ignored the new descriptions. Renamed the entries back to their `x86_dasm`/`find_*` identifiers and re-ran `./scripts/refresh_xzre_project.sh` so the richer comments now propagate into `xzregh/*.c` and the portable project archive.
- Next: audit the other metadata helpers for similar naming drift before adding more batch edits.

## 2025-11-15
- Completed the `opco_patt` batch RE pass: reread the x86 disassembler, prologue detectors, MOV/LEA/ADD pattern scanners, string-xref catalog builders, and reg-only helpers, then captured detailed AutoDoc narratives for all 18 functions in `metadata/functions_autodoc.json` so the descriptions now match the behaviour observed in `xzregh/*.c`.
- Ran `./scripts/refresh_xzre_project.sh` to replay the metadata into Ghidra, regenerate the exported C sources, and update `ghidra_projects/xzre_ghidra_portable.zip`.
- Next: extend `metadata/xzre_locals.json` for the opcode-scanner helpers so the refresh can rename the lingering `local_*` register temps inside the exported pattern-search routines.

## 2025-11-15
- Normalized all AutoDoc entries to wrap at 128 characters by scripting a metadata rewrite and re-running the headless refresh, so every `xzregh/*.c` block now renders as a readable multi-line comment that mirrors the JSON source of truth.
- Next: consider applying the same wrapping rules to any future helper scripts (e.g., stub generators) so manual edits keep the formatting consistent.

## 2025-11-15
- Completed the `crypto_cmd` batch RE pass: taught `scripts/generate_function_stubs.py` to fall back to short names, regenerated all 23 stubs, and filled in detailed notes covering the secret-data attestation helpers, sshbuf scanners, crypto primitives, and RSA/MM hooks.
- Rewrote the corresponding entries in `metadata/functions_autodoc.json` so every crypto_cmd function now documents the exact control flow (secret-data gating, sshbuf heuristics, Ed448 verification, etc.).
- Ran `./scripts/refresh_xzre_project.sh` to push the new metadata through headless Ghidra, regenerate the exported sources, and refresh the portable project snapshot.
- Next: extend `metadata/xzre_locals.json` for the sshbuf/secret_data helpers to replace the remaining `local_*` register temps before the next batch of exports.

## 2025-11-15
- Ran a fresh loader_rt RE sprint: regenerated the per-function stubs, reread every helper under `xzregh/10277*–10A80*`, and captured concise notes describing the GOT math, ld.so manipulation, cpuid glue, and runtime plumbing so the scratch files now reflect the latest understanding.
- Rewrote the AutoDoc metadata for the loader orchestrators (`init_hooks_ctx`, `init_imported_funcs`, `validate_log_handler_pointers`, `find_link_map_l_name`, `find_dl_naudit`, `process_shared_libraries_map`, `find_link_map_l_audit_any_plt*`, `find_dl_audit_offsets`) and added an explicit `xzre_globals` entry so the hooks blob/global context layout is documented inside `metadata/functions_autodoc.json`.
- Ran `./scripts/refresh_xzre_project.sh` to push the new metadata through Ghidra, regenerate `ghidra_scripts/generated/xzre_autodoc.json`, refresh `xzregh/*.c`, and update the portable project archive.
- Extended the locals metadata for the ld.so walkers and audit helpers (link_map candidates, naudit slot pointers, allocator handles, etc.) so the refresh now reuses descriptive names instead of `plVar*` placeholders, then re-ran the refresh to apply the new mapping.
- Fixed `scripts/apply_ghidra_comments_to_decomp.py` to fall back to `_name` variants so symbols like `_cpuid_gcc` finally pick up their AutoDoc blocks; re-applied the comments, confirmed both cpuid wrappers now render the tagged narrative, and re-exported the project archive.
- Next: chase down the lone function that still lacks an AutoDoc export per `apply_ghidra_comments_to_decomp.py` so the refresh stops emitting warnings.

## 2025-11-13
- Revalidated `xzregh/100020_x86_dasm.c` and found the helper still referenced `DAT_0010*` globals; traced the regression to the six opcode bitset entries in `metadata/linker_map.json` that were 0x50 bytes high relative to the actual rodata and rewrote their offsets to hit `dasm_threebyte_has_modrm`, `dasm_onebyte_is_invalid`, etc.
- Ran `./scripts/refresh_xzre_project.sh` so the linker-map fix propagated through the headless project export; `xzregh/100020_x86_dasm.c` now pulls from the named bitset tables and no longer leaves undefined identifiers behind in helper builds.
- Next: audit the rest of the `.rodata` entries inside `metadata/linker_map.json` for similar drift so future helpers never fall back to `DAT_*` placeholders.

## 2025-11-13
- Added the dasm opcode bitset globals to `metadata/linker_map.json`, corrected their offsets so the headless rename script stops aiming 0x10 bytes past the real rodata, and taught `metadata/xzre_types.json` to declare each table (`dasm_threebyte_has_modrm`, `dasm_onebyte_is_invalid`, etc.) for downstream helpers.
- Compared every `.rodata*` DEFSYM in `xzre.lds.in` against the actual section offsets reported by `readelf -W -S xzre/liblzma_la-crc64-fast.o`; each one sits +0x60 from the linker-script value (e.g., `dasm_twobyte_is_valid` lives at 0xAD80 instead of 0xAD20, `string_action_data` starts at 0xAF00 instead of 0xAEA0). Updated `metadata/linker_map.json` with the measured offsets and reran `./scripts/refresh_xzre_project.sh` so RenameFromLinkerMap.py re-labels the right addresses.
- Ran `./scripts/refresh_xzre_project.sh` twice (once to validate the metadata wiring, again after the offset fix); the exported `xzregh/100020_x86_dasm.c` now references the named tables instead of `DAT_0010*`, and the refreshed `xzre_types.h` advertises the new `extern const u8 [...]` declarations.
- Next: sweep the other `.rodata` DEFSYM2 ranges in `metadata/linker_map.json` to confirm their offsets are also normalized before we rely on those names inside additional helpers.

## 2025-11-13
- Named the previously anonymous unions (`x86_rex_prefix_t`, `x86_prefix_state_t`, `x86_modrm_info_t`, `Elf64_DynValue`, `audit_symbind_fn_t`, etc.) inside `metadata/xzre_types.json` so exported helpers stop declaring `_union_*` locals.
- Ran `./scripts/refresh_xzre_project.sh`; the regenerated headers now expose the new typedefs and `rg '_union_' xzregh` returns no matches (e.g., `xzregh/100020_x86_dasm.c` uses `x86_rex_prefix_t` and `xzregh/105830_backdoor_setup.c` assigns an `audit_symbind_fn_t`).
- Next: audit the remaining `field*_0x*` placeholders in the audit and sshd structs so future decomp diffs stay readable without manual type maps.

## 2025-11-13
- Introduced named function-pointer typedefs for every stubbed import (`pfn_getuid_t`, `pfn_EVP_DecryptInit_ex_t`, `dl_audit_symbind_alt_fn`, etc.) and rewired `metadata/xzre_types.json` plus the related locals metadata so the decompiler no longer emits `_func_<num>` placeholders.
- Regenerated the project via `./scripts/refresh_xzre_project.sh`; exported sources (`xzregh/104AE0_find_link_map_l_audit_any_plt_bitmask.c`, `xzregh/104EE0_find_link_map_l_audit_any_plt.c`, `xzregh/107DE0_sshd_configure_log_hook.c`) now reference the descriptive typedefs, and `rg '_func_' xzregh` returns no matches.
- Next: extend the locals metadata for any remaining helper stubs so future additions automatically inherit the named pointer types without manual fixes.

## 2025-11-13
- Fixing the parameter/local regressions: `ImportXzreTypes.py` was aborting because `sshd_ctx_t` referenced `sshd_payload_ctx_t` before that typedef existed, so none of the downstream ApplySignatures/ApplyLocals steps ran and Ghidra fell back to default names. Added a simple `va_list` typedef and moved the payload typedef ahead of `sshd_ctx_t` in `metadata/xzre_types.json` so the parser completes again.
- Reran `./scripts/refresh_xzre_project.sh`; the import now succeeds, and the exported helpers regained the real argument/local names (spot-checked `xzregh/100EB0_find_lea_instruction.c` and `100F60_find_lea_instruction_with_mem_operand.c`).
- Next: resolve the lingering `metadata/functions_autodoc.json` vs `xzre_autodoc.json` diff so refresh stops warning about mismatched comments.

## 2025-11-13
- Synced `metadata/functions_autodoc.json` with the fresh `ghidra_scripts/generated/xzre_autodoc.json` export to clear the persistent refresh warning about mismatched AutoDoc text.
- Re-ran `./scripts/refresh_xzre_project.sh --check-only`; the run now exits cleanly (only the usual external-function warnings) and no longer reports AutoDoc diffs.
- Next: fold any new narrative edits into the metadata first before running refresh so the generated file never diverges again.

## 2025-11-13
- Replaced the last `_unknown*` blobs in the string/payload metadata and the sshd/global-context structs: `string_item_t` now exposes `entry_bytes`, `key_ctx_t` splits the digest/nonce scratch, `sshd_ctx_t` has named pending-payload fields plus an explicit `pending_authpayload` pointer, and `global_context_t`/`sshd_log_ctx_t` now use explicit padding/flags instead of raw offsets.
- Updated the auxiliary structs (`elf_functions_t`, `fake_lzma_allocator_t`, `instruction_search_ctx_t`) to use reserved slots as well, then reran `./scripts/refresh_xzre_project.sh` so helpers like `elf_find_string_references.c` and `run_backdoor_commands.c` immediately pick up the new field names.
- Next: keep peeling back the remaining padding arrays elsewhere in `xzre_types.h` so future diffs stay type-driven.

## 2025-11-13
- Finished mapping the dasm-context scratch space: `metadata/xzre_types.json` now exposes the SIB byte (`sib_byte`, `sib_scale_bits`, `sib_index_bits`, `sib_base_bits`), the four-byte opcode window, and a named branch-displacement buffer, so the decomp no longer references `field_0x21`/`_unknown81*`.
- Reran `./scripts/refresh_xzre_project.sh`; the regenerated helpers show the new names in action (e.g., `x86_dasm` assigns into `ctx->sib_*` at xzregh/100020_x86_dasm.c:180 and the MOV/LEA scanners read the opcode window via `*(int *)(dctx->opcode_window + 3)` while consuming `dctx->mem_disp` for branch targets at xzregh/100F60_find_lea_instruction_with_mem_operand.c:36).
- Next: tackle the remaining `_unknown*` blobs inside the `string_item_t`/`backdoor_data_t` chain so the string-reference bookkeeping stops relying on raw byte offsets.

## 2025-11-13
- Reworked the `dasm_ctx_t` metadata so the prefix/REX/ModRM and SIB unions have descriptive field names, eliminating the bogus `field2_0x10` accessors that leaked into the decompilations.
- Ran `./scripts/refresh_xzre_project.sh` to push the updated types into Ghidra, regenerate `xzregh/*.c`, and refresh the portable project archive; the MOV/LEA helpers now reference `prefix.decoded.*` as expected.
- Added explicit opcode window fields (`opcode_history[]`, `opcode_window_high`, and `opcode_signature_bytes[]`) so the exported helpers no longer reference the imaginary `field_0x2b` byte; verified via another full refresh.
- Next: keep mapping the remaining anonymous decoder scratch bytes (e.g., `_unknown810`, `field_0x2b`) back to their real opcode state so future cleanups stay metadata-driven.

## 2025-11-08
- Added a `skip_locals` flag to `metadata/xzre_locals.json`, updated `ApplyLocalsFromXzreSources.py` to honor it, and taught `scripts/extract_local_variables.py` to carry arbitrary extra keys forward when regenerating the metadata, so we can intentionally suppress symbols that don’t exist in `liblzma_la-crc64-fast.o` without losing the annotations on the next rebuild.
- Marked all 363 functions that currently fail the locals pass (OpenSSL provider hooks, ossl_check helpers, dormant loader utilities, etc.) with `skip_locals: true` so the headless refresh now skips them quietly until we import binaries that actually define those symbols.
- Documented the workflow tweak in `AGENTS.md`/`README.md` so future analysts know how to re-enable the entries once additional objects are brought into the project.
- Next: re-enable individual entries by clearing `skip_locals` whenever we begin analyzing a binary that contains the corresponding function.

## 2025-11-07
- Added `register_temps` metadata to `metadata/xzre_locals.json` (loader helpers, ELF walkers, state guards, etc.) and introduced `scripts/postprocess_register_temps.py` so the refresh pipeline renames Ghidra’s synthetic `bVar*` temps (and fixes `(bool *)` casts) immediately after each export. The new step runs automatically inside `refresh_xzre_project.sh`.
- Updated `AGENTS.md` and `README.md` with instructions for recording register temps and documented the new post-processing phase so future runs stay metadata-driven.
- Next: capture any additional temp rename requests inside the JSON rather than editing `xzregh/*.c` by hand.

## 2025-11-07
- Completed the `loader_rt` sweep: reread every loader/GOT/audit helper plus the cpuid bootstrap path, rewrote their AutoDoc entries with the new findings (GOT math, ld.so walk, hook orchestration, syscall wrappers, cpuid glue, etc.), and added a first-class description for the exported `xzre_globals` blob so downstream tools know what lives inside the liblzma data segment.
- Added locals coverage for the same set—naming the key link_map pointers, audit helpers, shared context blocks, and libc import stubs—so the refresh now emits meaningful symbols instead of `puVar*` placeholders throughout `xzregh/10277*–10A80*`.
- Ran `./scripts/refresh_xzre_project.sh` to push the documentation/locals into the headless project, regenerate the exported decompilations, and update `ghidra_projects/xzre_ghidra_portable.zip`.
- Next: decide whether to resurrect the `xzre_globals.c` export (the cleaner wipes it each run) or keep documenting the data layout purely via `xzre_types.h` + metadata.

## 2025-11-07
- Finished a full RE pass over the `sshd_recon` batch: re-read every exported function under `xzregh/10255*–10A3A0` to document the monitor-struct locators, sensitive-data scorers, payload hooks, and log/command shims, then rewrote the matching entries in `metadata/functions_autodoc.json` so each one now spells out the heuristics, state transitions, and libcrypto/libc dependencies they rely on.
- Added locals coverage for the same set inside `metadata/xzre_locals.json` (allocator state, monitor pointers, socket probes, payload buffers, etc.) so future refreshes stop emitting the generic `local_*` symbols in those recon routines.
- Ran `./scripts/refresh_xzre_project.sh` to push the refreshed metadata through Ghidra, regenerate `xzregh/*.c`, and rebuild the portable project/archive with the richer docs and named locals.
- Next: extend the same treatment to the remaining hook batches (`loader_rt` / `crypto_cmd`) once we need deeper coverage on those stages.

## 2025-11-07
- Pruned the stale metadata aliases in `metadata/functions_autodoc.json` (e.g., `call_instruction`, `data_append_*`, `payload_message`, `libc_imports`, etc.) and renamed the remaining stragglers (`cpuid_gcc`→`_cpuid_gcc`, `get_cpuid_modified`→`_get_cpuid_modified`, `tls_get_addr`→`__tls_get_addr`) so every AutoDoc key now maps to an actual symbol in `liblzma_la-crc64-fast.o`.
- Ran `./scripts/refresh_xzre_project.sh` plus a `--check-only` pass to verify `ApplyAutoDocComments.py` reports zero “missing functions”; the headless export now attributes 125 comments with no warnings.
- Next: if we re-import other binaries later, revisit the metadata to add entries for any newly discovered symbols rather than resurrecting the legacy alias scheme.

## 2025-11-07
- Restored the locals-mapping step inside `scripts/refresh_xzre_project.sh` by chaining `ApplyLocalsFromXzreSources.py` into the initial headless import, so the curated entries from `metadata/xzre_locals.json` flow back into the project instead of leaving the autogenerated `uVar*` names in the exported `.c`.
- Reran the full refresh (and a sandboxed `--check-only`) to confirm the change: Ghidra now reports `Locals applied: 112 updated, 2 skipped, 362 functions missing`—the missing set corresponds to symbols absent from `liblzma_la-crc64-fast.o`—and regenerated files such as `xzregh/1013D0_elf_parse.c` once again show locals like `hash_bloom`, `gnu_hash`, `d_pltrelsz`, etc.
- Next: keep enriching `metadata/xzre_locals.json` when new binaries land; the pipeline will now pick up whatever we add there automatically.

## 2025-11-07
- Added a cleanup phase to `scripts/refresh_xzre_project.sh` so it `find`/deletes every `.c` under `xzregh/` before `ExportFunctionDecompilations.py` runs, keeping the export directory pristine and eliminating `_01` suffix churn between refreshes.
- Reran the refresh script to verify the purge happens automatically and that the exporter repopulates the directory with a single copy of each function; `rg '_01.c' xzregh` now returns empty.
- Next: relocate any hand-maintained `.c` helpers out of `xzregh/` (or teach the cleanup step to skip specific filenames) since the wipe will remove every C source under that directory on each refresh.

## 2025-11-07
- Reworked `ExportFunctionDecompilations.py` to use `codecs.open(..., encoding="utf-8")` plus `unicode_literals` so every header/comment string is emitted as Unicode, then reran `./scripts/refresh_xzre_project.sh` to verify the exporter completes without `UnicodeEncodeError`.
- The refresh now succeeds end-to-end; it re-generated the `_01` suffixed dumps in `xzregh/`, so expect a fresh batch of files after each run unless we later add an overwrite mode.
- Next: decide whether to teach the exporter to clobber existing files (or to clean the output directory) so routine refreshes don’t accumulate `*_01.c` debris.

## 2025-11-07
- Switched `ExportFunctionDecompilations.py` to open output files via `io.open(..., encoding="utf-8")` so non-ASCII glyphs (e.g., em dashes in AutoDoc text) no longer trigger `UnicodeEncodeError` during the export phase.
- Next: rerun the refresh pipeline to confirm the headless exporter now survives functions whose comments include extended characters, and keep an eye out for any other scripts still relying on ASCII defaults.

## 2025-11-07
- Hardened `ExportFunctionDecompilations.py` so the optional `types=` header copy skips when the source and destination paths resolve to the same file, fixing the runtime `shutil.Error` that appeared once the refresh pipeline began exporting directly into `xzregh/`.
- Next: monitor the next refresh run to ensure the header is still copied when exporting to alternate directories (e.g., check-only sandboxes) and consider adding a warning if the header is missing entirely.

## 2025-11-07
- Wired `ExportFunctionDecompilations.py` into `scripts/refresh_xzre_project.sh` so every refresh now re-runs the full decomp export (with `xzre_types.h` copied alongside) before AutoDoc comments are re-applied to `xzregh/*.c`.
- The new invocation respects `--check-only` by targeting a temporary `xzregh` directory, ensuring the sandbox run mirrors production without dirtying the repo.
- Next: keep an eye on runtime; if the export starts to dominate refresh time we may need a `--skip-decomp` knob for quick metadata-only iterations.

## 2025-11-07
- Identified the `hash_buckets` local in `elf_parse` as the GNU hash header cursor and updated `metadata/xzre_locals.json` so the slot is typed as `gnu_hash_table_t *`, aligning the decomp with the struct defined in `xzregh/xzre_types.h`.
- Ran `./scripts/refresh_xzre_project.sh` to push the refreshed locals metadata through the Ghidra project, regenerate the portable archive, and sync the text dumps / generated helpers.
- Noted that the zero-init loop in `elf_parse` is walking the `elf_info_t` storage, so the `*(undefined4 *)hash_bloom = 0;` construct stems from Ghidra’s scalarized memset; leave it as-is unless we later teach the scripts to recognize custom memset patterns.
- Next: keep scanning the remaining `elf_mem` locals for struct matches (e.g., relocation iterators, segment cursors) before diving into the loader batches again.

## 2025-11-07
- Enumerated every type token referenced across `xzregh/*.c` (all `_t` suffixed identifiers plus the ssh/BOOL/u8-style helpers) and compared the 52 unique names against `metadata/xzre_types.json`; only `uchar`, `ushort`, `uint`, `ssh`, and `sshbuf` lacked canonical typedefs.
- Added those typedefs (including `typedef struct ssh ssh;` and `typedef struct sshbuf sshbuf;`) so the generated `xzregh/xzre_types.h` exposes the OpenSSH aliases and unsigned integer shorthands, then reran `./scripts/refresh_xzre_project.sh` to regenerate the Ghidra project, export header, and refreshed `.c` dumps.
- Left a note that future cleanups should tackle the remaining `_func_*` placeholders so imported function pointers get readable typedefs instead of opaque auto names.
- Next: follow up on the `_func_*` typedef mapping or continue expanding the metadata coverage for the other dependency batches.

## 2025-11-07
- Fixed the headless AutoDoc/TypeDoc sync: the Ghidra scripts still used CPython-only `encoding=` kwargs (and ASCII-only `str()` coercions) so every refresh silently failed under Jython, which is why `xzregh/*.c` never picked up the new metadata. Swapped the readers over to `codecs.open(...)` and removed the lossy coercions so ApplyAutoDoc/ApplyTypeDocs/ExportAutoDocComments now run end-to-end.
- Added a `types=<path>` option to `ghidra_scripts/ExportFunctionDecompilations.py`, letting the export pass copy `xzre_types.h` (or any other header) alongside the per-function `.c` dumps so consumers always get the struct definitions with the decomp output.
- Taught `scripts/apply_ghidra_comments_to_decomp.py` to enforce a `#include "xzre_types.h"` line (and to strip whatever AutoDoc block currently sits at the file prologue), so every exported function now carries the header include automatically whenever the refresh pipeline runs.
- Reran `./scripts/refresh_xzre_project.sh` to confirm the patched pipeline applies the richer docs across the 120+ exported functions and to regenerate the portable project/archive with the synchronized comments.
- Next: keep iterating on the remaining metadata batches now that the pipeline reliably propagates edits; the new CLI flag can be wired into any future export automation that needs the header materialized next to the functions.

## 2025-11-07
- Completed the `elf_mem` RE pass by rewriting 30 metadata entries covering the ELF parsers, relocation scanners, fake liblzma allocator, and TLS shims so the plate comments now spell out the recursion limits, range checks, and relocation bookkeeping the loader performs.
- Re-ran `./scripts/refresh_xzre_project.sh` to propagate the richer documentation into the Ghidra project, regenerated `xzregh/*`, and built a fresh portable archive.
- Next: tackle the remaining dependency batch (e.g., `sshd_recon` or `loader_rt`) to keep pushing detailed behaviour notes through the metadata store before diving into locals/type cleanups.

## 2025-11-07
- Reviewed the entire `opco_patt` batch and rewrote 18 entries in `metadata/functions_autodoc.json` with detailed behaviour notes for the custom decoder, call/MOV/LEA scanners, string-reference harvesters, and ELF helper routines so the plate comments mirror what the decompiler now shows.
- Ran `./scripts/refresh_xzre_project.sh` to push the refreshed metadata through the headless import, regenerate `xzregh/*`, and export the portable snapshot with the new documentation in place.
- Next: continue with the next dependency batch (e.g., `elf_mem`) so the remaining helper families gain the same level of coverage before tackling locals/typing follow-ups.

## 2025-11-07
- Captured the linker-script map into `metadata/linker_map.json` (extracted from `xzre/xzre.lds.in`) so the refresh pipeline can restore function/data names without touching the upstream tree.
- Updated `ghidra_scripts/RenameFromLinkerMap.py` to read that JSON (while keeping the legacy `.lds` parser as a fallback) and wired `scripts/refresh_xzre_project.sh` to require the metadata file, which removes the last pipeline dependency on `xzre/` aside from the object file itself.
- Next: remove the `xzre/` checkout once the standalone `liblzma_la-crc64-fast.o` is cached someplace safe.

## 2025-11-07
- Expanded `scripts/extract_local_variables.py` so it now walks both `xzre/xzre_code/` and the top-level `xzre/*.c` sources (with fallbacks for missing `loc.file` metadata and graceful skips for files that can’t be parsed), enabling locals coverage for every exported function that has upstream C.
- Regenerated `metadata/xzre_locals.json` via the updated script, which boosted the catalog from 33 to 396 functions and added 105 newly recovered local variable names for import into Ghidra/xzregh.
- Ran `./scripts/refresh_xzre_project.sh` to copy the refreshed metadata into the headless project, apply the locals, and re-export the decompiled sources plus the portable archive.
- Next: investigate how to capture locals for the remaining helper sources (e.g., `ssh_patch.c` currently skipped because `libunwind.h` isn’t installed) so the metadata stays complete.

## 2025-11-06
- Introduced `metadata/type_docs.json` plus support in `scripts/manage_types_metadata.py` to inject structured comments before every typedef/enum/struct when regenerating `xzregh/xzre_types.h` and `ghidra_scripts/xzre_types_import_preprocessed.h`, then annotated the xzre-specific types and enums with summaries and usage notes.
- Added `ghidra_scripts/ApplyTypeDocs.py` and taught `scripts/refresh_xzre_project.sh` to feed the doc JSON to both the header renderer and the Ghidra headless run so the descriptions now land inside the datatype manager as well as the exported header.
- Ran `./scripts/refresh_xzre_project.sh` to verify the new doc pipeline, regenerate the portable project, and confirm the type descriptions apply cleanly inside the database.
- Next: flesh out docs for any newly discovered types directly in `metadata/type_docs.json` before running the refresh to keep the header and database synchronized.

## 2025-11-06
- Added `scripts/manage_types_metadata.py` plus the canonical `metadata/xzre_types.json` so typedefs/enums/structs (and the associated externs) now live in JSON; regenerated both `xzregh/xzre_types.h` and `ghidra_scripts/xzre_types_import_preprocessed.h` from that metadata which also stripped the stray placeholder semicolons from the headers.
- Updated `scripts/refresh_xzre_project.sh` to rebuild the import/decomp headers from the JSON on every run, keeping Ghidra and `xzregh/` in sync without hand-editing generated artifacts.
- Next: rerun the refresh script to confirm the regenerated headers import cleanly and start iterating on the JSON when new structure insights land.

## 2025-11-06
- Enriched `metadata/functions_autodoc.json` with backdoor-focused documentation for every `xzregh` function so the exported plate comments now describe behaviour and how each routine is used.
- Ran `./scripts/refresh_xzre_project.sh` to propagate the updated metadata into the Ghidra project and regenerate the textual dumps.
- Next: skim the refreshed project to ensure the new comments read correctly and note any functions that still need locals or typing fixes for a later pass.

## 2025-11-06
- Pruned the pre-metadata tooling by deleting `scripts/annotate_xzre_decomp.py` plus the legacy reports pipeline (`reports/*.json`, `scripts/map_locals.py`, `scripts/tolerant_signature_compare.py`, `ghidra_scripts/ExportUnmappedFunctionSummaries.py`, `ghidra_scripts/ApplyFunctionAnnotationsFromJson.py`, related docs); all documentation and locals updates now flow through the metadata JSONs before rerunning the refresh pipeline — next: backfill any lingering AutoDoc gaps directly in the metadata store.

## 2025-11-06
- Staged the metadata-first pipeline: added `scripts/build_autodoc_from_sources.py`, moved locals to `metadata/xzre_locals.json`, populated the canonical `metadata/functions_autodoc.json` (seeded from sources + existing plate comments), updated `scripts/refresh_xzre_project.sh` to copy metadata→Ghidra→xzregh, and documented the workflow in `AGENTS.md` — next: review the metadata JSON for completeness and begin refining entries (arguments, locals, struct details) there before re-running the refresh.

## 2025-11-06
- Pivoted the AutoDoc flow so the Ghidra project drives downstream docs: added `ghidra_scripts/ExportAutoDocComments.py`, `scripts/apply_ghidra_comments_to_decomp.py`, and taught `scripts/refresh_xzre_project.sh` to re-export plate comments from the project before syncing `xzregh/*.c` — next: run `./scripts/refresh_xzre_project.sh` to validate the round-trip and confirm the exported JSON feeds both Ghidra and the text dumps.

## 2025-11-06
- Wired AutoDoc into the headless pipeline: extended `scripts/annotate_xzre_decomp.py` to emit `ghidra_scripts/generated/xzre_autodoc.json`, added `ghidra_scripts/ApplyAutoDocComments.py`, and updated `scripts/refresh_xzre_project.sh` so refresh runs now stamp the comments directly into the Ghidra project — next: run the refresh script to bake the new plate comments into `xzre_ghidra.rep` and confirm they survive export.

## 2025-11-06
- Added `scripts/annotate_xzre_decomp.py` and ran it (`python3 scripts/annotate_xzre_decomp.py --max-snippet-lines 80`) so every `xzregh/*.c` gains an AutoDoc block with the upstream header docs plus an excerpt of the original implementation, giving analysts precise behavioural context for variable renaming — next: wire the annotator into the refresh/export flow to keep comments current whenever the Ghidra dump regenerates.

## 2025-11-06
- Mirrored the Ghidra type import into `xzregh/xzre_types.h` and added `xzregh/xzre_globals.c` with raw `.rodata`/`.bss` dumps so exported decompilations have matching struct definitions and data references — next: decide whether to automate regeneration of these artifacts inside `scripts/refresh_xzre_project.sh` to keep future updates in sync.

## 2025-11-06
- Added `ghidra_scripts/ExportUnmappedFunctionSummaries.py` and ran it headlessly to emit `reports/unmapped_functions.json`; the report captures four unmapped extern thunks (`lzma_alloc`/`lzma_free`/`lzma_check_init`/`__tls_get_addr`) with parameter/storage details plus brief descriptions so we can reconcile their prototypes against upstream before the next typing pass — next: decide whether to fold those externs into the linker map or treat them as imported helpers when applying argument names.
- Extended the exporter to append mapped-but-missing functions from `xzre_locals.json`; the report now notes `backdoor_symbind64` (with its source path and locals) so the same pipeline can track future gaps when we start replaying local-variable fixes — next: repeat the run after each refresh to keep the missing-function list in sync.
- Built `ghidra_scripts/ApplyFunctionAnnotationsFromJson.py` and ran it with `reports/unmapped_functions.json`; the headless pass updated parameter datatypes for the four extern thunks and re-exported `ghidra_projects/xzre_ghidra_portable.zip`, giving us a reproducible way to replay these annotations once additional function bodies arrive — next: expand the JSON entries with local-variable shapes as we ingest more objects so the script can rename stack slots automatically.
- Added `ghidra_scripts/ExportFunctionDecompilations.py` and dumped every function to `xzregh/` (one `.c` file per entry point, with prototype metadata) so we can diff decomp output or hand-edit variable cues without launching Ghidra — next: wire this exporter into future refresh runs if we want a rolling textual snapshot for version control.

## 2025-11-05
- Added a quick headless helper (`ghidra_scripts/PrintFunctionDecompile.py`) to dump decompiler output plus raw instructions so we could sanity-check `backdoor_entry`; confirmed the binary writes the `_cpuid_gcc` EAX result to the local at `[rbp-0x4c]` and returns it, matching the source even though the applied locals currently label that slot as `b` — next: adjust the locals mapping (or tweak the apply script) so `a/b/c/d` land on their intended stack slots and avoid future confusion.
- Reworked the locals pipeline so `map_locals.py` keeps declaration order stable and `ApplyMappedLocals.py` now stages conflicting renames through temporary placeholders; reran both scripts and confirmed `backdoor_entry` decompiles with `_cpuid_gcc(...,&a,&b,&c,&state)` and `return a` again — next: audit other functions with overlapping stack reuse to make sure the new rename logic doesn’t need additional heuristics.

## 2025-11-04
- Adjusted `scripts/map_locals.py` so register-only locals defer to the dedicated matcher instead of the generic type-mismatch fallback, then ran `python scripts/map_locals.py --limit 200` to regenerate `reports/variable_mapping_report.json`; register temporaries now pick up confident matches without caveats — next: extend the alias heuristics again if future binaries surface new register edge cases.
- Replayed `ApplyMappedLocals.py` headlessly with the refreshed report (`~/tools/ghidra_11.4.2_PUBLIC/support/analyzeHeadless ... mapping=reports/variable_mapping_report.json`); 51 locals updated and 52 noted for follow-up, lining up the remaining register-only names with the `c_strnlen::len` fix — next: audit the skipped entries to decide whether additional heuristics or manual reviews are warranted.
- Ported the GUI rename flow into `ApplyMappedLocals.py` by invoking `HighFunctionDBUtil.updateDBVariable` for high-level symbols, re-ran the targeted `c_strlen` mapping, and then replayed the full report; register-only locals (including return-value temporaries) now rename cleanly and the global apply pass dropped to 12 skips — next: spot-check the remaining skips to see if they need new heuristics or manual intervention.
- Expanded `scripts/map_locals.py` heuristics (size hints, signed/unsigned aliasing, pointer-depth guard) and taught `ApplyMappedLocals.py` to preserve stack-array types during renames; regenerated the mapping report and re-applied locals (diagnostic run now reports only the expected low-confidence skips plus the missing `backdoor_symbind64`) — next: decide whether to tune array-length matching further or leave those manual.

## 2025-10-31
- Expanded `ghidra_scripts/RenameFromLinkerMap.py` so it now captures `.rodata*` and other non-text sections, which let the refresh pipeline stamp the branch-table symbols (`dasm_*`, `string_action_data`, `string_mask_data`, etc.) straight from `xzre.lds.in` — next: add explicit coverage for any data not represented in the linker script if we bring in additional objects.
- Added `ghidra_scripts/InstallEnumEquates.py` and wired it into `scripts/refresh_xzre_project.sh`; each refresh now parses `xzre_types_import_preprocessed.h` to install equates for `EncodedStringId` and the `CommandFlags{1,2,3}` enums so constant operands decompile with names instead of raw hex — next: consider extending the parser to cover additional flag enums if we expand the signature coverage.

## 2025-10-31
- Enhanced `ghidra_scripts/RenameFromLinkerMap.py` to parse section metadata so `.data*`/`.bss*` entries from `xzre/xzre.lds.in` now create or rename the corresponding globals, then reran `scripts/refresh_xzre_project.sh` to regenerate `ghidra_projects/xzre_ghidra_portable.zip` with the new labels applied (headless log shows 7 data symbols updated) — next: decide whether to bring the `.rodata` branch-table labels in through the same path.

## 2025-10-31
- Removed the automated locals extraction/apply steps from `scripts/refresh_xzre_project.sh` and re-ran the refresh so the headless pipeline now stops after signatures/parameter fixes; this keeps Ghidra’s SSA-local naming untouched for manual curation while still exporting an updated portable project — next: revisit locals application once a reliable merge strategy is scripted.

## 2025-10-31
- Hardened `ghidra_scripts/ApplyLocalsFromXzreSources.py` to clear conflicting stack slots safely, grow frames for large arrays, and only reuse candidates when they closely match the requested type; the refreshed headless pass now applies all 75 mapped locals without skips (only `backdoor_symbind64` remains absent from the object) — next: fold the new heuristics into `scripts/refresh_xzre_project.sh` runs so future imports keep the locals aligned automatically.
- Added `ghidra_scripts/VerifyLocalsAgainstMapping.py` for a headless sanity check that cross-references `ghidra_scripts/generated/xzre_locals.json`; verification shows full coverage aside from the expected missing `backdoor_symbind64` — next: ingest the binary providing that symbol or map an alias so the locals report stays clean.

## 2025-10-31
- Reworked `ghidra_scripts/ApplyLocalsFromXzreSources.py` to purge conflicting stack slots, generate fresh locals from `ghidra_scripts/generated/xzre_locals.json`, and resolve type strings via inline C parsing; `scripts/refresh_xzre_project.sh` now reports 75 locals applied with zero skips (only `backdoor_symbind64` is absent from the compiled object) and the exported `ghidra_projects/xzre_ghidra_portable.zip` carries the update — next: ingest the object or alias that defines `backdoor_symbind64` so the locals map reaches full coverage.
- Added `ghidra_scripts/DumpFunctionLocals.py` for headless spot-checks of stack layouts and used it to verify `elf_parse` and `rsa_key_hash` after the refresh, keeping regressions easy to triage without launching the GUI — next: fold the script into review steps whenever `ghidra_scripts/generated/xzre_locals.json` changes.
- Eliminated the `WARNING: Variable defined which should be unmapped` spam by teaching `ApplySignaturesFromHeader.py` to mark functions with imported prototypes as using custom variable storage and wiring a new `FixAllParamStorage.py` pass into `scripts/refresh_xzre_project.sh`; parameters now report assigned register storage across the board, and `ListProblemVariables.py`/`DumpFunctionParams.py` give a quick sanity check when the headers change — next: keep an eye on future imports that introduce new entry points so the custom-storage fix stays in place.

## 2025-10-31
- Hooked `RenameFromLinkerMap.py` into the refresh pipeline before signature replay (and hardened `ApplyLocalsFromXzreSources.py` for array types) so re-importing the object no longer strips the xzre symbol names; signature coverage is back to 100%, and the locals script now applies cleanly (31 locals updated, 1 function missing because it lacks locals in this build) — next: watch for any future object drops that omit those symbols so we can decide whether to gate the locals step.
- Added `scripts/extract_local_variables.py` plus the headless helper `ghidra_scripts/ApplyLocalsFromXzreSources.py`, regenerated the local-variable JSON map, and wired both into `scripts/refresh_xzre_project.sh` so every refresh replays the xzre decompiled locals; functions without compiler-emitted locals are skipped automatically, but the generated map is ready for richer objects if/when we import them — next: bring in the object that contains the remaining backdoor routines (or reconcile their symbol names) to expand coverage further.
- Created `scripts/refresh_xzre_project.sh` and documented it in `AGENTS.md` so every headless refresh re-imports the object, reapplies xzre headers, invokes `ApplySignaturesFromHeader.py`, and exports the portable archive in one step — next: wire the helper into any CI/automation that rebuilds the investigation workspace.
- Extended `ghidra_scripts/ApplySignaturesFromHeader.py` so every headless signature refresh now assigns the compiler's default System V AMD64 calling convention to any remaining `unknown` functions, keeping ABI warnings suppressed automatically — next: consider pruning the standalone `SetDefaultCallingConvention.py` once downstream workflows have migrated to the integrated path.
- Confirmed the `x86:LE:64` gcc compiler spec maps its default `__stdcall` prototype to the System V AMD64 ABI, added helper scripts (`ListCallingConventionNames.py`, `ListUnknownCallingConventions.py`, `SetDefaultCallingConvention.py`), fixed 125 functions with unknown conventions, verified the cleanup headlessly, and refreshed `ghidra_projects/xzre_ghidra_portable.zip` — next: fold the default-convention script into any future signature import workflows so reimports stay warning-free.
- Added `ghidra_scripts/ListFunctionSignatures.py` and ran it headlessly to dump all `liblzma_la-crc64-fast.o` prototypes, then diffed the output against `ghidra_scripts/xzre_types_import_preprocessed.h` — uncovered 31 mismatches (missing const qualifiers, typedef drift like `uint` vs `unsigned int`, and the `secret_data_append_items` appender callback type) that still need to be resolved before the database matches upstream.
- Built `ghidra_scripts/InspectFunctionTypes.py` plus scratch script `TestParseConst.py` to inspect the active signature datatypes; reapplying the header definitions confirmed that the remaining gaps are cosmetic quirks in Ghidra’s C parser (it canonicalises `const` away, folds `struct` tags into typedef names, and renders function-pointer callbacks as typedef pointers). No functional mismatches remain, so further changes would require upstream adjustments to the parser or accepting alternative renderings — Next: document the acceptable deltas in any downstream comparison tooling if strict textual equality is required.

## 2025-10-30
- Added the nine missing extern prototypes (`__tls_get_addr`, `elf_contains_vaddr_impl`, `elf_find_rela_reloc`, `elf_find_relr_reloc`, `hook_EVP_PKEY_set1_RSA`, `hook_RSA_get0_key`, `j_tls_get_addr`, `lzma_check_init`, `lzma_free`) into `xzre/xzre.h`, regenerated `ghidra_scripts/xzre_types_import_preprocessed.h`, reran the import/signature pass, and refreshed the portable archive — Ghidra now reports zero missing prototypes with the OpenSSL hooks now typed against forward-declared structs for const-correctness.
- Ran `ImportXzreTypes.py` headlessly against `ghidra_scripts/xzre_types_import_preprocessed.h` so every xzre function signature and related typedef now lives in the `liblzma_la-crc64-fast.o` program — this aligns Ghidra’s database with the upstream headers for cleaner decompilation.
- Regenerated `ghidra_projects/xzre_ghidra_portable.zip` via `ExportProjectArchive.py` to capture the refreshed project state — next: review the decompiler output for comment/annotation passes.
- Added helper scripts (`ghidra_scripts/ListDefaultNamedFunctions.py`, `ghidra_scripts/ListAllFunctions.py`, `ghidra_scripts/RenameFromLinkerMap.py`) and ran the rename pass so every function now matches its identifier from `xzre/xzre.lds.in` (default-name count dropped to zero) — next: extend `xzre.h`/import headers for the remaining `// FIXME: prototype` entries and annotate high-priority routines.
- Created `ghidra_scripts/ApplySignaturesFromHeader.py` (plus `ListFunctionDefinitions.py` for sanity checks) and applied header prototypes to 116 functions via headless Ghidra.

## 2025-10-29
- Imported sanitized xzre headers via `ghidra_scripts/ImportXzreTypes.py` to register typedefs/enums/structs for the program in `liblzma_la-crc64-fast.o` — ensures Ghidra has all backdoor type information needed for signature work — Next: align the actual function prototypes with these imported data types.
- Added headless export script (`ghidra_scripts/ExportProjectArchive.py`) and generated `ghidra_projects/xzre_ghidra_portable.zip` to snapshot the project without committing live `.rep` state.
- Created the headless Ghidra project `xzre_ghidra` under `ghidra_projects/` and imported `xzre/liblzma_la-crc64-fast.o` using `~/tools/ghidra_11.4.2_PUBLIC/support/analyzeHeadless`.

## Update Template
- `YYYY-MM-DD`: <What changed?> — <Why it was done?> — <Next action if applicable>
