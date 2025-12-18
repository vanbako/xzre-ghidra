# Progress Log

Document notable steps taken while building out the Ghidra analysis environment for the xzre artifacts. Add new entries in reverse chronological order and include enough context so another analyst can pick up where you left off.

## 2025-12-18
- Session `CC4` revisit: corrected `secret_data_append_from_instruction`’s opcode filter write-up (MOV/CMP + ALU mask) and clarified that the bitstream is ORed into `global_ctx->encrypted_secret_data`; also aligned `secret_data_append_singleton` AutoDoc with the `shift_operation_flags`/`secret_bits_filled` field names. Updated `metadata/functions_autodoc.json` and `docs/FUNCTION_PROGRESS.md`; validated with `./scripts/refresh_xzre_project.sh --check-only` and refreshed via `./scripts/refresh_xzre_project.sh` (rename report: `ghidra_scripts/generated/locals_rename_report.txt`, portable archive: `ghidra_projects/xzre_ghidra_portable.zip`). Next: move on to `CC5` (secret data appenders II) or reconcile the remaining `secret_data` vs. `encrypted_secret_data` naming drift in AutoDoc/type docs.
- Session `CC3` revisit: cleaned up the RSA hook batch by rewriting the last lingering `undefined1` CONCAT cast in `run_backdoor_commands` and seeding `do_orig_flag = TRUE;` in `hook_EVP_PKEY_set1_RSA`/`hook_RSA_get0_key` for readability. Updated `metadata/xzre_locals.json` and `docs/FUNCTION_PROGRESS.md`; refreshed via `./scripts/refresh_xzre_project.sh` (rename report: `ghidra_scripts/generated/locals_rename_report.txt`, portable archive: `ghidra_projects/xzre_ghidra_portable.zip`). Next: move on to `CC4` (secret data appenders I) or revisit `run_backdoor_commands` to swap the remaining stack0/CONCAT header extracts for typed field accesses.
- Session `CC2` revisit: tightened the sshbuf-recovery helpers by renaming `sshd_get_sshbuf`’s scan end pointer (`pkex_scan_end`), documenting the monitor pkex_table dword override, the 0x400-byte scan, and the known-slot fast path inline; clarified `sshbuf_extract`’s size-field selection; and rewrote `verify_signature`’s digest-scratch wipe store to an explicit zero so the ECDSA fingerprint path reads as a memzero loop. Updated `metadata/functions_autodoc.json`, `metadata/xzre_locals.json`, and `docs/FUNCTION_PROGRESS.md`; refreshed via `./scripts/refresh_xzre_project.sh` (rename report: `ghidra_scripts/generated/locals_rename_report.txt`, portable archive: `ghidra_projects/xzre_ghidra_portable.zip`). Next: move on to `CC3` (backdoor RSA hooks) or pivot back to the struct tracker.
- Session `CC1` revisit: clarified the scratch-buffer wipe split in `dsa_key_hash` and rewrote `rsa_key_hash`’s wipe cursor base to `fingerprint_stream + 0x10` (avoids the misleading `&result` stack slot), keeping the full 0x10+tail clear behaviour obvious in the exported C. Updated `metadata/functions_autodoc.json`, `metadata/xzre_locals.json`, and `docs/FUNCTION_PROGRESS.md`; validated with `./scripts/refresh_xzre_project.sh --check-only` and refreshed via `./scripts/refresh_xzre_project.sh` (rename report: `ghidra_scripts/generated/locals_rename_report.txt`, portable archive: `ghidra_projects/xzre_ghidra_portable.zip`). Next: continue with `CC2` (signature checks & sshbuf helpers) or pivot back to the struct tracker.
- Session `LR6` revisit: cleaned up the stage-two I/O helpers by renaming `fd_read`/`fd_write` scratch temps (`bytes_read`/`bytes_written`, `errno_ptr`, `bytes_remaining`), renaming `contains_null_pointers`’ slot pointer to `slot_ptr`, and adding inline anchors for the zero-count fast paths plus the shared `-1` failure sentinel. Updated `metadata/functions_autodoc.json`, `metadata/xzre_locals.json`, and `docs/FUNCTION_PROGRESS.md`; validated with `./scripts/refresh_xzre_project.sh --check-only` and refreshed via `./scripts/refresh_xzre_project.sh` (rename report: `ghidra_scripts/generated/locals_rename_report.txt`, portable archive: `ghidra_projects/xzre_ghidra_portable.zip`). Next: start `CC1` (crypto primitives) or pivot back to the struct tracker.
- Session `LR5` revisit: corrected the CPUID helper exports by documenting `_cpuid_gcc` as a thin `cpuid` instruction wrapper (Ghidra leaf pseudo-functions), fixing `backdoor_entry`'s CPUID out-arg naming/ordering, and removing the `(uint *)&state` scratch pointer from the exported `_cpuid_gcc` call; also simplified `count_pointers`' probe-index increment. Updated `metadata/xzre_types.json`, `metadata/functions_autodoc.json`, `metadata/xzre_locals.json`, and `docs/FUNCTION_PROGRESS.md`; validated with `./scripts/refresh_xzre_project.sh --check-only` and refreshed via `./scripts/refresh_xzre_project.sh` (rename report: `ghidra_scripts/generated/locals_rename_report.txt`, portable archive: `ghidra_projects/xzre_ghidra_portable.zip`). Next: continue with the loader runtime helpers (LR6) or pivot back to the struct tracker.
- Session `LR4`: clarified the ld.so audit/stage-two wiring by naming `ldso_ctx_t.libcrypto_basename_buf`, rewriting `find_link_map_l_audit_any_plt` to use `*(u32 *)&insn_ctx.opcode_window[3]` instead of the `_40_4_` overlay, collapsing constant-zero wipe strides in the LR4 exports, and adding inline anchors for the `backdoor_setup` struct wipes. Updated `metadata/xzre_types.json`, `metadata/functions_autodoc.json`, `metadata/xzre_locals.json`, `docs/FUNCTION_PROGRESS.md`, and `docs/STRUCT_PROGRESS.md`; validated with `./scripts/refresh_xzre_project.sh --check-only` and refreshed via `./scripts/refresh_xzre_project.sh` (rename report: `ghidra_scripts/generated/locals_rename_report.txt`, portable archive: `ghidra_projects/xzre_ghidra_portable.zip`). Next: revisit `backdoor_init_stage2`/`backdoor_init` once more to make sure the cpuid fallback path and relocation-const usage are fully documented, then move on to LR5.
- Implemented forced stack-offset locals support in `ghidra_scripts/ApplyLocalsFromXzreSources.py` (`stack_offset` + `force_stack`) so we can model stack-resident structs that Ghidra originally split into field-sized locals. Updated `scripts/extract_local_variables.py` to preserve per-local override keys on regen, documented the new knobs in `AGENTS.md`, and applied the feature to `process_shared_libraries` by pinning `tmp_state` to `-0x40` in `metadata/xzre_locals.json`. Validated with `./scripts/refresh_xzre_project.sh --check-only` and refreshed via `./scripts/refresh_xzre_project.sh`; `xzregh/104A40_process_shared_libraries.c` now decompiles with a single `tmp_state` struct instead of the unused `debug_block`/`local_*` field surrogates.
- Session `LR3` revisit: corrected `process_shared_libraries` AutoDoc/inline notes to key off `_r_debug.r_version` (not `r_state`), added targeted `metadata/xzre_locals.json` postprocess rewrites so `xzregh/104A40_process_shared_libraries.c` seeds/uses the stack `tmp_state` fields (`shared_maps`, `elf_handles`, output slots) instead of the misleading `r_debug_sym`/`debug_block` temporaries, and simplified the decoder-context wipe cursor advances in `find_dl_naudit` + `find_link_map_l_audit_any_plt_bitmask` (removed the zero-multiplied stride). Updated `metadata/functions_autodoc.json`, `metadata/xzre_locals.json`, and `docs/FUNCTION_PROGRESS.md`, validated with `./scripts/refresh_xzre_project.sh --check-only`, then refreshed via `./scripts/refresh_xzre_project.sh` (rename report: `ghidra_scripts/generated/locals_rename_report.txt`, portable archive: `ghidra_projects/xzre_ghidra_portable.zip`). Next: finish LR3 by tightening `process_shared_libraries_map`/`resolve_libc_imports` (link_map field offsets, remaining guard rationale) or move on to LR4 (audit offsets & stage two).

## 2025-12-17
- Session `LR2` revisit: clarified the GOT-math helpers by rewording the 0x2600 seed as the `ff 25` opcode tag (0x25ff+1), renaming `update_got_address`’s prefix probes to `has_endbr64_prefix`/`jmp_opcode_offset` while documenting the `.got.plt` base computation (disp32 − 0x18), and retitling the `find_link_map_l_name` heuristics locals (`best_name_ptr`, etc.) plus its plate to capture the RELRO-anchored `l_name` offset recovery. Updated `metadata/functions_autodoc.json`, `metadata/xzre_locals.json`, and `docs/FUNCTION_PROGRESS.md`, validated with `./scripts/refresh_xzre_project.sh --check-only`, then refreshed via `./scripts/refresh_xzre_project.sh` (rename report: `ghidra_scripts/generated/locals_rename_report.txt`, portable archive: `ghidra_projects/xzre_ghidra_portable.zip`). Next: continue with LR3 (link-map walks) or scrub the remaining `Elf64_Ehdr::e_ident` pointer-math noise in the loader exports.
- Session `LR1` revisit: corrected `init_ldso_ctx`’s AutoDoc to describe how cleanup restores libcrypto’s `link_map::l_name` pointer away from the forged basename buffer (back to the auditstate slot address), added an inline note for the decoder-scratch wipe in `validate_log_handler_pointers`, and retyped `lea_insn_size` to `u64` for clearer pointer arithmetic. Updated `metadata/functions_autodoc.json`, `metadata/xzre_locals.json`, and `docs/FUNCTION_PROGRESS.md`, then refreshed via `./scripts/refresh_xzre_project.sh` (rename report: `ghidra_scripts/generated/locals_rename_report.txt`, portable archive: `ghidra_projects/xzre_ghidra_portable.zip`). Next: continue with LR2 (GOT math) or do a second pass over LR1’s remaining scratch locals to reduce the lingering pointer-cast noise in `xzregh/102B10_validate_log_handler_pointers.c`.
- Session `SR5`: clarified `mm_answer_authpassword_hook`’s synthetic monitor reply framing (big-endian length word, cached reqtype, 1-byte auth_ok, optional root_allowed dword) and renamed the stack temps accordingly; renamed the unused local that shadowed `global_ctx` inside `mm_answer_keyallowed_hook` to `global_ctx_ptr` so the exported C no longer emits `::global_ctx` while keeping the inline anchors stable; tightened a misleading inline note in `mm_log_handler_hook`. Updated `metadata/functions_autodoc.json`, `metadata/xzre_locals.json`, and `docs/FUNCTION_PROGRESS.md`, validated with `./scripts/refresh_xzre_project.sh --check-only`, then refreshed via `./scripts/refresh_xzre_project.sh` (rename report: `ghidra_scripts/generated/locals_rename_report.txt`, portable archive: `ghidra_projects/xzre_ghidra_portable.zip`). Next: reconcile the `sshd_ctx_t` tail-field meanings used by the auth/keyverify hook restore paths, then pivot back to the loader/struct tracker.
- Session `SR4`: tightened the runtime patching/payload helpers by retyping `sshd_patch_variables`’s PAM pointer as `int *`, expanding `extract_payload_message`’s AutoDoc to call out the 7-byte prefix scan plus the modulus-tail/mpint-leading-zero guards, and renaming `sshd_proxy_elevate`’s 32-byte cert-alg scratch to `rsa_cert_alg_prefix` while correcting the exponent/modulus wording. Updated `metadata/functions_autodoc.json`, `metadata/xzre_locals.json`, and `docs/FUNCTION_PROGRESS.md`, validated with `./scripts/refresh_xzre_project.sh --check-only`, then refreshed via `./scripts/refresh_xzre_project.sh` (rename report: `ghidra_scripts/generated/locals_rename_report.txt`, portable archive: `ghidra_projects/xzre_ghidra_portable.zip`). Next: either finish a second pass over `check_backdoor_state`/`sshd_configure_log_hook` or move on to SR5 (monitor message hooks).
- Session `SR3` follow-up: cleaned up the process-vetting/log plumbing helpers by fixing `process_is_sshd`’s envp cursor cast to `char **` (plus a new inline anchor for the envp start), renaming `sshd_log`’s SysV varargs `AL` byte to `xmm_vararg_count` while documenting the full `sshlogv(file, func, line, showfunc, ...)` signature, and tightening `sshd_get_usable_socket`’s AutoDoc to call out the intentionally invalid `shutdown()` probe that avoids mutating socket state. Updated `metadata/functions_autodoc.json`, `metadata/xzre_locals.json`, and `docs/FUNCTION_PROGRESS.md`, then validated with `./scripts/refresh_xzre_project.sh --check-only` and refreshed via `./scripts/refresh_xzre_project.sh` (rename report: `ghidra_scripts/generated/locals_rename_report.txt`, portable archive: `ghidra_projects/xzre_ghidra_portable.zip`). Next: move on to SR4 (patch variables + payload flow) or continue the `Elf64_Ehdr::e_ident` pointer-math cleanup sweep.
- Session `SR2` revisit: corrected SR2 scoring/monitor metadata by renaming the `main()` field-hit booleans to `host_*_hit` (matching `sensitive_data->host_keys/host_pubkeys/host_certificates`), fixing the AutoDoc to describe the returned 0–3 hit count (rather than a signed score), clarifying that monitor discovery votes on the `.data/.bss` slot stored in `ctx->monitor_struct_slot`, and rewriting the `EVP_DigestVerify` resolve to `(u8 *)libcrypto->elfbase + st_value` (dropping the lingering `Elf64_Ehdr::e_ident` base-pointer hack). Validated with `./scripts/refresh_xzre_project.sh --check-only`, then refreshed via `./scripts/refresh_xzre_project.sh` (rename report: `ghidra_scripts/generated/locals_rename_report.txt`, portable archive: `ghidra_projects/xzre_ghidra_portable.zip`). Next: scrub the remaining `Elf64_Ehdr::e_ident` pointer math across the ELF/loader helpers (grep `e_ident +` in `xzregh/`).
- Session `SR1` revisit: cleaned up the SR1 sshd recon helpers (`sshd_find_main`, monitor-field finder, the KRB5CCNAME/xcalloc probes, and the `do_child` scorer) by adding `register_temps` replacements that remove the remaining `Elf64_Ehdr::e_ident` base-pointer hacks and simplify the decoder wipe cursor increments. Validated with `./scripts/refresh_xzre_project.sh --check-only`, then refreshed via `./scripts/refresh_xzre_project.sh` (rename report: `ghidra_scripts/generated/locals_rename_report.txt`, portable archive: `ghidra_projects/xzre_ghidra_portable.zip`). Next: keep pushing the same pointer-math cleanup through the remaining ELF/loader helpers until no `e_ident` hacks remain in `xzregh/`.
- Session `EL6` revisit: corrected `get_lzma_allocator` AutoDoc to describe how callers patch `allocator->opaque` and use `lzma_alloc()`/`lzma_free()` as the fake symbol-resolver interface (backed by `fake_lzma_alloc`/`fake_lzma_free`). Validated with `./scripts/refresh_xzre_project.sh --check-only`, then refreshed via `./scripts/refresh_xzre_project.sh` (rename report: `ghidra_scripts/generated/locals_rename_report.txt`, portable archive: `ghidra_projects/xzre_ghidra_portable.zip`).
- Session `EL5` revisit: cleaned up `main_elf_parse`’s `__libc_stack_end` pointer math to `(void **)((u8 *)elf->elfbase + st_value)` (dropping the `Elf64_Ehdr::e_ident` byte-pointer hack) via `metadata/xzre_locals.json`, corrected the `get_elf_functions_address` AutoDoc plate to match the `fake_lzma_allocator_offset` sentinel, and clarified `_Lrc_read_destroy` as the relocation-safe cpuid anchor in `init_elf_entry_ctx`. Validated with `./scripts/refresh_xzre_project.sh --check-only`, then refreshed via `./scripts/refresh_xzre_project.sh` (rename report: `ghidra_scripts/generated/locals_rename_report.txt`, portable archive: `ghidra_projects/xzre_ghidra_portable.zip`).
- Session `EL4` revisit: corrected `elf_contains_vaddr_relro`’s prototype/documentation so the boolean gate is named `require_relro` and the containment check is described as PF_W (writable PT_LOAD) rather than PF_R. Updated `metadata/xzre_types.json` + `metadata/functions_autodoc.json`, validated with `./scripts/refresh_xzre_project.sh --check-only`, then refreshed via `./scripts/refresh_xzre_project.sh` (rename report: `ghidra_scripts/generated/locals_rename_report.txt`, portable archive: `ghidra_projects/xzre_ghidra_portable.zip`).
- Session `EL3`: fixed `elf_find_relr_reloc`’s prototype to accept `void *target_addr` plus explicit `[slot_lower_bound, slot_upper_bound]` + `resume_index_ptr`, matching `elf_find_rela_reloc` and eliminating pointer casts at call sites. Also rewrote the RELR/reloc-slot base math via `metadata/xzre_locals.json` so the exported C uses `(u8 *)elfbase` / `(u8 *)elf_info->elfbase` instead of `Elf64_Ehdr::e_ident`, updated the stale inline AutoDoc match anchor, and refreshed via `./scripts/refresh_xzre_project.sh` (rename report: `ghidra_scripts/generated/locals_rename_report.txt`, portable archive: `ghidra_projects/xzre_ghidra_portable.zip`).
- Session `EL2`: fixed `elf_find_rela_reloc`’s signature to accept `void *target_addr` plus explicit `[slot_lower_bound, slot_upper_bound]` + `resume_index_ptr`, eliminating the CONCAT44 high-word temp and making the optional clamp/resume behavior visible at call sites. Also codified the `Elf64_Ehdr::e_ident` byte-pointer hacks as `(u8 *)elfbase`/`(u8 *)elf_info->elfbase` in locals metadata (RELA walker + `elf_symbol_get_addr`) and refreshed the AutoDoc plate. Refreshed via `./scripts/refresh_xzre_project.sh` and confirmed the output is clean (rename report: `ghidra_scripts/generated/locals_rename_report.txt`, portable archive: `ghidra_projects/xzre_ghidra_portable.zip`).
- Session `EL1` revisit: tightened the ELF containment/parser baseline by rewriting `elf_contains_vaddr_impl`’s exported pointer arithmetic to plain `u8 *` math (dropping the `Elf64_Ehdr::e_ident` byte-pointer hacks) and expanding `elf_parse` with inline AutoDoc anchors for the key DT_* dynamic tags + dyn-entry stride. Refreshed via `./scripts/refresh_xzre_project.sh` and confirmed the output is clean (rename report: `ghidra_scripts/generated/locals_rename_report.txt`, portable archive: `ghidra_projects/xzre_ghidra_portable.zip`).
- Session `OP4` revisit: cleaned up `elf_find_string_references` by encoding the remaining `.text` pointer arithmetic fixes in `metadata/xzre_locals.json` (text-end calc, next-instruction cursor, RIP-target math) and correcting `entry_cursor` to `string_references_t *`, eliminating the lingering `decode_cursor->instruction`/`->opcode_window` decompiler artifacts. Refreshed via `./scripts/refresh_xzre_project.sh` and confirmed the output is clean (rename report: `ghidra_scripts/generated/locals_rename_report.txt`, portable archive: `ghidra_projects/xzre_ghidra_portable.zip`).
- Session `OP3` revisit: revisited the memory-operand sweep helpers by clarifying the RIP-relative disp32 gate (ModRM `mod=0`, `rm=5`) + `DF2_MEM_DISP` semantics in AutoDoc, correcting the `find_add_instruction_with_mem_operand` opcode write-up (`0x103` = raw `0x83` GRP1 imm8), and simplifying the scratch `dasm_ctx_t` wipe cursor arithmetic via `metadata/xzre_locals.json`. Also fixed stale inline-match anchors so the missing REX.W/range guard comments reapply in `xzregh/102C60_find_addr_referenced_in_mov_instruction.c` and `xzregh/104370_find_dl_naudit.c`. Refreshed via `./scripts/refresh_xzre_project.sh` (rename report: `ghidra_scripts/generated/locals_rename_report.txt`, portable archive: `ghidra_projects/xzre_ghidra_portable.zip`).
- Next: start session `LR1` (init contexts & imports) now that `elf_mem` is refreshed end-to-end.

## 2025-12-16
- Session `OP2` revisit: tightened the MOV/LEA pattern helpers by correcting the decoded ModRM constraint (`mod=0`, `rm=5` → RIP-relative disp32), documenting the decoder opcode normalization (+0x80) in each AutoDoc, and fixing `find_reg2reg_instruction`’s opcode whitelist write-up (MOV reg↔reg plus ADD/OR/ADC/SBB/SUB/XOR/CMP). Updated `metadata/functions_autodoc.json`, normalized `enum X86_OPCODE` + docs in `metadata/xzre_types.json`/`metadata/type_docs.json`, and refreshed via `./scripts/refresh_xzre_project.sh` (rename report: `ghidra_scripts/generated/locals_rename_report.txt`, portable archive: `ghidra_projects/xzre_ghidra_portable.zip`).
- Next: continue with session `OP3` (memory operand sweeps) or chase the remaining inline-match warnings noted by the refresh.
- Session `OP1` revisit: cleaned up the core opcode-scanner helpers by simplifying the scratch `dasm_ctx_t` wipe cursor arithmetic in `x86_dasm`, `find_function_prologue`, and `find_call_instruction`, renaming `x86_dasm`’s lingering byte scratch (`bVar2` → `cursor_byte`), and adding inline AutoDoc anchors for the VEX prefix parse + ModRM decode. Updated `metadata/xzre_locals.json`/`metadata/functions_autodoc.json` and refreshed via `./scripts/refresh_xzre_project.sh` (rename report: `ghidra_scripts/generated/locals_rename_report.txt`, portable archive: `ghidra_projects/xzre_ghidra_portable.zip`).
- Next: continue with session `OP2` (MOV/LEA pattern searchers) or chase the remaining inline-match warnings noted by the refresh.
- Session `STRUCT_instruction_search_register_bitmaps`: modeled the audit matcher’s register bitmap/offset overlays by adding `instruction_register_bitmap_t` + `instruction_search_offset_t` to `metadata/xzre_types.json`, retagging `instruction_search_ctx_t`, and updating `metadata/xzre_locals.json`/`metadata/functions_autodoc.json` so `xzregh/104EE0_find_link_map_l_audit_any_plt.c` + `xzregh/104AE0_find_link_map_l_audit_any_plt_bitmask.c` now export named members (`offset_to_match.dwords.offset`, `bitmap.fields.allowed_regs`, `bitmap.fields.reg_index`) with inline AutoDoc anchors restored. Refreshed via `./scripts/refresh_xzre_project.sh` (rename report: `ghidra_scripts/generated/locals_rename_report.txt`, portable archive: `ghidra_projects/xzre_ghidra_portable.zip`).
- Next: optionally clean up the remaining inline-match warnings (`xzregh/102C60_find_addr_referenced_in_mov_instruction.c`, `xzregh/104370_find_dl_naudit.c`) or pick the next struct backlog item.
- Fixed fallout from the `dasm_ctx_t.prefix` overlay pass by re-aligning `x86_dasm` register-temp renames in `metadata/xzre_locals.json` (restored `opcode_ptr`, `opcode_high_bits`, `opcode_class_mask/entry`, `ctx_zero_stride`, `range_hits_upper_bound`, `modrm_byte`, etc.) and reran `./scripts/refresh_xzre_project.sh` to confirm `xzregh/100020_x86_dasm.c` exports cleanly again (rename report: `ghidra_scripts/generated/locals_rename_report.txt`).
- Session `STRUCT_dasm_ctx_t.prefix`: expanded `x86_prefix_state_t` in `metadata/xzre_types.json` with `flags_u32` + a byte-level `modrm_bytes` overlay (REX/ModRM breakdown) and cleaned up `metadata/xzre_locals.json` now that the prefix `_N_M_` slices are gone. Ran `./scripts/refresh_xzre_project.sh` and verified the exported scanners (`xzregh/104AE0_find_link_map_l_audit_any_plt_bitmask.c`, `xzregh/104EE0_find_link_map_l_audit_any_plt.c`, `xzregh/103680_sshd_get_sensitive_data_address_via_xcalloc.c`) now read `prefix.flags_u32`/`prefix.modrm_bytes.*` instead of `prefix._0_4_`/`prefix._14_1_` etc; portable archive regenerated at `ghidra_projects/xzre_ghidra_portable.zip`.
- Next: tackle the instruction-search bitmap/ctx overlays in `docs/STRUCT_BACKLOG.md` so the audit matcher stops mutating `_0_3_`/`_0_4_` byte slices.

## 2025-12-15
- Session `STRUCT_sshd_offsets_t`: mapped the four-byte packed offset cache (`kex_sshbuf_qword_index`, `monitor_pkex_table_dword_index`, `sshbuf_data_qword_index`, `sshbuf_size_qword_index`) and updated `metadata/xzre_types.json`/`metadata/type_docs.json` so `sshd_offsets_t` exports as a named union (`fields`/`bytes`/`raw_value`) with signed indices. Updated `metadata/xzre_locals.json` + `metadata/functions_autodoc.json` so `xzregh/107950_sshbuf_extract.c`, `xzregh/107A20_sshd_get_sshbuf.c`, and the opcode-0 offsets rewrite in `xzregh/1094A0_run_backdoor_commands.c` now export with direct member access (no `field0_0x0` pointer arithmetic) and refreshed inline AutoDoc anchors. Ran `./scripts/refresh_xzre_project.sh` and re-applied inline comments; portable archive regenerated at `ghidra_projects/xzre_ghidra_portable.zip`.
- Next: tackle the `dasm_ctx_t.prefix` overlays from `docs/STRUCT_BACKLOG.md` so the instruction scanners stop relying on raw `_N_M_`/prefix byte slices.
- Session `STRUCT_key_payload_t`: revisited the ChaCha payload framing by flattening `backdoor_payload_hdr_t` and `key_payload_t` in `metadata/xzre_types.json`, introducing the `key_payload_cmd_frame_t` scratch overlay for the RSA modulus staging path, and updating `metadata/xzre_locals.json`/`metadata/functions_autodoc.json` so `xzregh/108D50_decrypt_payload_message.c` and the relevant `run_backdoor_commands` blocks export with readable field/byte accesses and refreshed inline comments. Ran `./scripts/refresh_xzre_project.sh` and re-applied inline anchors; portable archive regenerated at `ghidra_projects/xzre_ghidra_portable.zip`.
- Next: tackle `sshd_offsets_t` from `docs/STRUCT_BACKLOG.md` so the payload dispatch path stops relying on raw byte indexing for monitor/kex/sshbuf offsets.

## 2025-11-27
- Session `ENUM_audit_pattern_state`: defined the `audit_pattern_state_t` enum inside `metadata/xzre_types.json`, retagged the `pattern_state` register temp in `metadata/xzre_locals.json`, and ran `./scripts/refresh_xzre_project.sh` so `xzregh/104AE0_find_link_map_l_audit_any_plt_bitmask.c` now declares `audit_pattern_state_t pattern_state` and the generated `xzregh/xzre_types.h` exports the new LEA/MOV/TEST state constants; also struck the backlog entry in `docs/ENUM_ENUMERATION_BACKLOG.md` after verifying the Ghidra export/portable archive.
- Follow-up: added literal replacements so the decomp now prints `AUDIT_PAT_EXPECT_*` instead of raw integers (assignments + comparisons), refreshed `metadata/functions_autodoc.json` inline matches, and reran the pipeline to confirm the updated names land cleanly in `xzregh/104AE0*.c` plus the portable archive.
- Next: tee up the next enum/struct backlog item (or continue expanding the loader structs) now that the audit scanner FSM is represented in metadata.

## 2025-11-27
- Session `ENUM_monitor_reqtype`: mirrored OpenSSH’s `monitor_reqtype` enum into `metadata/xzre_types.json` (plus the `_t` typedef), retagged `sshd_ctx_t`’s authpassword/keyallowed opcode fields, the `sshd_patch_variables` prototype, and the `op_result` local in `metadata/xzre_locals.json`, then ran `./scripts/refresh_xzre_project.sh` so `ghidra_scripts/xzre_types_import_preprocessed.h`, `xzregh/xzre_types.h`, `xzregh/107D50/108EA0/1094A0*.c`, and the portable archive now show the `MONITOR_REQ_*` names instead of raw ints; cleared the backlog entry afterwards.
- Next: move on to the next backlog item (`audit_pattern_state_t`) so the audit scanner stops juggling anonymous integers for its FSM.

## 2025-11-27
- Session `ENUM_payload_command_type`: defined the attacker payload command enum in `metadata/xzre_types.json` (plus the `payload_command_type_t` typedef), retagged `sshd_payload_ctx_t::command_type`, and updated `metadata/xzre_locals.json` so `mm_answer_keyallowed_hook` now names the `payload_type` temp and rewrites the opcode branches to use `PAYLOAD_COMMAND_*` constants. Reran `./scripts/refresh_xzre_project.sh` until the rename/replacement warnings cleared; `xzregh/108EA0_mm_answer_keyallowed_hook.c`, `xzregh/xzre_types.h`, `ghidra_scripts/xzre_types_import_preprocessed.h`, and the portable archive all show the symbolic enum.
- Next: continue down `docs/ENUM_ENUMERATION_BACKLOG.md` (likely `monitor_reqtype_t`) so the monitor structs/hooks stop comparing raw request IDs.

## 2025-11-27
- Session `ENUM_payload_state`: introduced the `payload_stream_state_t` enum in `metadata/xzre_types.json`, updated `global_context_t.payload_state` plus the associated register temps in `metadata/xzre_locals.json`, and ran `./scripts/refresh_xzre_project.sh` twice so the regenerated `xzregh/107EA0_check_backdoor_state.c`, `xzregh/108EA0_mm_answer_keyallowed_hook.c`, `xzregh/108D50_decrypt_payload_message.c`, and `xzregh/xzre_types.h` now show the symbolic state names (rename report stayed green, portable archive refreshed). Marked the backlog entry as complete once the export looked good.
- Next: keep working down `docs/ENUM_ENUMERATION_BACKLOG.md` (likely `payload_command_type_t` or `monitor_reqtype_t`) so the remaining payload/monitor guards stop comparing raw integers.

## 2025-11-27
- Session `CC7`: purged every remaining `undefined*` local/cast from the active sshd/RSA pipeline (`run_backdoor_commands`, the mm hooks, `sshd_proxy_elevate`, `decrypt_payload_message`, `sshd_log`, `backdoor_setup`, etc.) by retagging the offending locals/temps in `metadata/xzre_locals.json`, adding replacement rewrites for the BSS/stack wipes and opcode header packing, and updating the inline anchors in `metadata/functions_autodoc.json`. Ran `./scripts/refresh_xzre_project.sh` twice (second pass picked up the new inline substrings) so `xzregh/*.c`, the locals rename report, and the portable archive now emit real `u8/u16/u32/u64` types with no injector warnings.
- Next: sweep the remaining batches for `undefined*` mentions inside the inline comment matches (e.g., the loader_rt helpers still referencing the old memset strings) so future metadata edits don't regress the injector.

## 2025-11-27
- Session `CC6`: scrubbed the lingering `undefined[0-9]` wipes in `rsa_key_hash`, `verify_signature`, `secret_data_get_decrypted`, `secret_data_append_from_code`, and `secret_data_append_singleton` by adding the requisite `register_temps` replacements plus new inline anchors for the digest/seed/shift guards, then reran `./scripts/refresh_xzre_project.sh` so `xzregh/*`, the headless project, the locals rename report, and the portable archive all reflect the typed rewrites with no injector warnings.
- Next: tackle the remaining crypto_cmd holdouts (especially `run_backdoor_commands` and the continuation helpers) to finish purging `undefined*` stores before pivoting back to the struct tracker.

## 2025-11-27
- Session `LR7`: scrubbed the loader batch for lingering `undefined*` locals by retagging the search-context wipes and register scratchpads in `find_link_map_l_audit_any_plt`, `_bitmask`, `find_dl_naudit`, `validate_log_handler_pointers`, `backdoor_init`, and `backdoor_init_stage2`. Added new inline anchors for the search-context zeroing, decoder reset, resolver-frame stash, and CPUID fallback capture inside `metadata/functions_autodoc.json`, renamed the cpuid relocation pointer plus the register temps in `metadata/xzre_locals.json`, and reran `./scripts/refresh_xzre_project.sh` (x3 while chasing the inline substring) so `xzregh/104EE0/104AE0/104370/102B10/10A794/106F30.c`, the rename report, and the portable archive now emit typed `u32` stores instead of raw `undefined` casts.
- Next: keep marching through the remaining loader_rt helpers (e.g., the giant `backdoor_setup` zeroing loops and GOT repair routines) so no `undefined*` wipes remain before pivoting to the struct tracker for the loader structs.

## 2025-11-27
- Session `SR1` revisit: swept `sshd_find_main`, `_find_monitor_field_addr_in_function`, `_get_sensitive_data_address_via_krb5ccname`, `_via_xcalloc`, and `_score_in_do_child` to eliminate the lingering `undefined[0-9]` wipes. Added `register_temps` replacements so every decoder zeroing loop now emits typed `u32` stores, documented each reset with new inline comment anchors, bumped the FUNCTION_PROGRESS review counts, and reran `./scripts/refresh_xzre_project.sh` so `xzregh/102550/102FF0/103340/103680/103870*.c`, the locals rename report, and the portable archive all mirror the cleaned-up metadata.
- Next: continue the sshd recon backlog by repeating the `undefined*` scrub + inline pass on the SR2 batch (score aggregator/monitor struct helpers) before moving on to the more complex SR3 socket/log routines.

## 2025-11-27
- Session `EL_mem_cleanup`: revisited `elf_parse` to kill the lingering `undefined[0-9]` vector temps—introduced named 128-bit scratch buffers for the PLT/RELA divisor math, rewrote the wipe loop to emit typed `u32` stores, added inline anchors for the PT_GNU_RELRO uniqueness guard and the `.gnu.version_d` drop logic, refreshed `metadata/xzre_locals.json`, `metadata/functions_autodoc.json`, and `docs/FUNCTION_PROGRESS.md`, then reran `./scripts/refresh_xzre_project.sh` so `xzregh/1013D0_elf_parse.c`, the locals rename report, and the portable archive all reflect the typed scratchpads without postprocess warnings.
- Next: keep scanning the remaining `elf_mem` helpers for any other `undefined*` leftovers (especially the RELRO/data segment walkers) before pivoting back to the sshd recon backlog.

## 2025-11-27
- Session `OP_cleanup`: scrubbed every `opco_patt` decoder helper that still emitted `undefined[0-9]` casts by adding `register_temps` replacements for the scratch ctx wipes/opcode window stores, rewrote the operand-size override mask inside `x86_dasm`, and dropped a fresh inline comment on the `.text` sweep in `elf_find_string_references`. Updated `metadata/functions_autodoc.json`, `metadata/xzre_locals.json`, and the FUNCTION_PROGRESS table, then reran `./scripts/refresh_xzre_project.sh` so `xzregh/*`, the Ghidra project, portable archive, and locals rename report all reflect the typed rewrites.
- Next: finish the remaining OP4 bookkeeping (`elf_find_function_pointer`, `elf_find_string_reference`) or pivot to the next batch once the opco scanners stay clean.

## 2025-11-27
- Session `CC3` cleanup: retired the lingering `_union_110` placeholder in `run_backdoor_commands` by defining `sshd_hostkey_index_t` (metadata/types doc + struct tracker), retagging the locals metadata, wiring in a literal rewrite so casts become `.raw_value`, and rerunning `./scripts/refresh_xzre_project.sh` + the register-temp pass so `xzregh/xzre_types.h`, `ghidra_scripts/xzre_types_import_preprocessed.h`, and `xzregh/1094A0_run_backdoor_commands.c` now expose the named struct without inline-match warnings (followed by a quick fix in `verify_signature` after reapplying the rewrites).
- Next: sweep the other literal replacements in `metadata/xzre_locals.json` for idempotence (so ad-hoc register-temp passes stay safe) or continue marching through the CC3 backlog if no more anonymous unions pop up.

## 2025-11-27
- Session `CC3` revisit: focused on `run_backdoor_commands`, renamed the remaining `uVar*/bVar*/local_*` scratch (opcode field packers, payload-span counters, nonce/timespec/cmd_args buffers) via `metadata/xzre_locals.json`, added fresh inline anchors for the modulus-chunk clamp, PermitRootLogin override, and opcode-2 NUL terminator gate inside `metadata/functions_autodoc.json`, updated `docs/FUNCTION_PROGRESS.md`, and reran `./scripts/refresh_xzre_project.sh` so `xzregh/1094A0` plus the headless project/portable archive mirror the new names/comments without rename-report noise.
- Next: finish sweeping the CC3 batch by giving the RSA hook wrappers (`hook_RSA_public_decrypt`, `_EVP_PKEY_set1_RSA`) the same locals/inline treatment or pivot to the struct tracker (`sshd_payload_ctx_t`) once the dispatcher stabilizes.

## 2025-11-26
- Session `SR5` revisit: tightened `decrypt_payload_message` by renaming the ciphertext cursor/buffer append temps via `metadata/xzre_locals.json`, added inline anchors for the state-3 short-circuit, header copy, length/buffer clamps, and ChaCha double-pass commentary in `metadata/functions_autodoc.json`, and reran `./scripts/refresh_xzre_project.sh` until the inline injector stayed green (rename report clean, portable archive refreshed).
- Next: carry the same locals/inline treatment into `extract_payload_message`/`mm_answer_keyallowed_hook` so the payload staging pipeline is consistently documented.
- Session `CC3` follow-up: re-reviewed `run_backdoor_commands`, renamed the lingering register temps (`control_flags`, `command_opcode`, `payload_chunk_len`, `caller_uid`, `command_payload_ptr`, BN bitlen/FD-set cursors) via `metadata/xzre_locals.json`, added new inline anchors (opcode latch, 0x87-byte body clamp, root-only gate, `[uid||gid||cmd]` span check, monitor payload size, `pselect` socket wait) in `metadata/functions_autodoc.json`, updated `docs/FUNCTION_PROGRESS.md`, and reran `./scripts/refresh_xzre_project.sh` so `xzregh/1094A0_run_backdoor_commands.c`, the locals rename report, and the portable archive all carry the refreshed comments.
- Next: carry the same locals/inline coverage into the remaining RSA hook shims (`hook_RSA_public_decrypt`, `hook_EVP_PKEY_set1_RSA`, etc.) or pivot to the struct tracker (`run_backdoor_commands_data_t`, `sshd_payload_ctx_t`) once CC3 is fully wrapped.
- Session `CC3` deep dive: revisited `run_backdoor_commands`, renamed the modulus/command locals in `metadata/xzre_locals.json` (`rsa_modulus_bits/bytes`, `payload_buffer_cursor`, `socket_probe_header`, decrypted/encrypted payload buffers, rsa_modulus_bn/e), added the new opcode/uid/offset/mm_keyallowed inline comments to `metadata/functions_autodoc.json`, refreshed `docs/FUNCTION_PROGRESS.md`, and reran `./scripts/refresh_xzre_project.sh` so `xzregh/1094A0_run_backdoor_commands.c` mirrors the metadata update (rename report stayed green).
- Next: finish the CC3 backlog by pushing the same level of locals/inline coverage into the remaining RSA hook helpers or pivot to the struct tracker if the dispatcher no longer blocks that work.
- Session `LR4` follow-up: revisited `backdoor_setup`, renamed the packed string-id scratch qwords, added inline notes for the mm_request literal caching / relocation hunt plus the fake `malloc_usable_size` stub and sshlogv handover, and ran `./scripts/refresh_xzre_project.sh` (x3 while chasing the replacement warnings) until the rename report and inline injection finished cleanly; FUNCTION_PROGRESS now shows review count 3.
- Next: keep grinding through the LR4 backlog (e.g., validate whether `backdoor_init` needs the same literal-scan cleanup or pivot to the struct tracker once the loader batch is fully annotated).
- Session `LR4` touch-up: renamed the stack scratch structs in `backdoor_init_stage2` (`seed_shared_globals`, `bootstrap_hooks_ctx`, `setup_params_block`) via `metadata/xzre_locals.json`, refreshed the inline AutoDoc match strings to the new identifiers, and reran the pipeline so `xzregh/106F30_backdoor_init_stage2.c` carries the meaningful names (inline warnings cleared, rename report still green).
- Session `LR4` revisit: deepened the `backdoor_init_stage2` pass by enriching its AutoDoc entry (shared-globals seeding, `lzma_check_init()` bootstrap, cpuid leaf 0/1 fallback), renaming the lingering `extraout_*` register temps to `hooks_ctx_retry_*`, and threading fresh inline anchors through the shared-globals copy, dummy check init, and cpuid fallback sequences inside `metadata/functions_autodoc.json` / `metadata/xzre_locals.json`.
- Ran `./scripts/refresh_xzre_project.sh` once the metadata settled; the regenerated `xzregh/106F30_backdoor_init_stage2.c`, locals rename report, and `ghidra_projects/xzre_ghidra_portable.zip` all reflect the new names/comments, and `docs/FUNCTION_PROGRESS.md` now tracks the second review.
- Next: keep chipping away at the LR4 backlog (e.g., revisit `backdoor_init` or pivot to the struct tracker once the loader hooks stay fully annotated).

## 2025-11-25
- Session `CC3` revisit: tightened `run_backdoor_commands` by renaming the stack payload buffer/hostkey locals (`payload_plaintext_size`, `payload_plaintext`, `hostkey_idx`, `pselect_result`, `bytes_read`) and adding inline anchors for the PAM disable bit, system-exec opcode, monitor kill switch, and continuation chunk streaming path.
- Ran `./scripts/refresh_xzre_project.sh` twice to land the metadata (first pass flushed out a stale inline match; second pass was clean after updating the substring) so `xzregh/1094A0_run_backdoor_commands.c`, the locals rename report, and `ghidra_projects/xzre_ghidra_portable.zip` all carry the new comments/names.
- Next: keep iterating on the CC batch by codifying the remaining command-channel helpers (e.g., sanity-check `run_backdoor_commands_data_t` overlays or hop to the struct tracker once the dispatcher work stabilizes).

## 2025-11-25
- Session `SR4` revisit: reviewed `sshd_proxy_elevate`, renamed the lingering register temps (frame_scratch_iter, signature_word_cursor, sshbuf_size_cursor, zero_stride_flag, etc.) inside `metadata/xzre_locals.json`, and refreshed the AutoDoc/inline coverage to document the PermitRootLogin/PAM toggles, stack-hash hunt, secret-data unwrap, on-stack ChaCha decrypt, sshbuf continuation handling, and wait/drain logic directly in the exported C.
- Ran `./scripts/refresh_xzre_project.sh` multiple times while fixing inline match strings; the final pass finished cleanly (inline comments present, locals rename report still green, `ghidra_projects/xzre_ghidra_portable.zip` updated) and `docs/FUNCTION_PROGRESS.md` now records the second pass over this function.
- Next: keep tightening the SR4 backlog by propagating the new KEYALLOWED/monitor-frame insights into the neighbouring command-channel docs (e.g., `run_backdoor_commands`, struct notes) or pivot to the struct tracker once the remaining SR4 entries are refreshed.

## 2025-11-25
- Session `CC6`: introduced a dedicated `monitor_cmd_type_t` enum (control-plane, patch, system exec, proxy exchange) in `metadata/xzre_types.json`, retagged `monitor_data_t.cmd_type`, and updated the `sshd_proxy_elevate`/`run_backdoor_commands` register-temporary metadata so both decompilations now show the typed enum instead of raw integers.
- Ran `./scripts/refresh_xzre_project.sh` twice (the second pass picked up the renamed `cmd_type` register) so `xzregh/*.c`, the locals rename report, and `ghidra_projects/xzre_ghidra_portable.zip` all carry the new enum + metadata wiring.
- Next: consider propagating the new enum names into the rest of the command-channel docs (`docs/backdoor_functionality.md`, inline AutoDoc excerpts) so future opcode analysis references the shared constants.

## 2025-11-25
- Session `SR5` revisit: deep-dived `mm_log_handler_hook`, rewrote its plate to spell out both the Connection-closed pass-through and Accepted-line rewrites, added inline anchors for the disable gates, string-id scans, fragment copies, sshd_log replays, and setlogmask toggles, and renamed the lingering loop/copy temps in `metadata/xzre_locals.json`.
- Ran `./scripts/refresh_xzre_project.sh` to push the metadata into Ghidra/`xzregh`; the regenerated `xzregh/10A3A0_mm_log_handler_hook.c`, locals rename report, and `ghidra_projects/xzre_ghidra_portable.zip` all updated cleanly with the new comments/names.
- Next: continue the log-hook thread (e.g., validate `sshd_log_ctx_t`/`sshd_configure_log_hook` artifacts for any remaining metadata gaps) or pivot to the struct tracker once SR5 stays fully documented.

## 2025-11-25
- Session `LR4` follow-up: revisited `backdoor_setup`, renamed the hooks blob/log-handler/PAM/root-tracking locals (`hooks_data`, `string_id_cursor`, `log_handler_slot_candidate`, etc.) in `metadata/xzre_locals.json`, and expanded `metadata/functions_autodoc.json` with new plate text plus inline anchors for the auth-log relocation hunt, PAM flag capture, root-vote gate, secret_bits audit guard, and cpuid reset.
- Ran `./scripts/refresh_xzre_project.sh` to push the metadata into Ghidra/`xzregh`—inline comments landed cleanly, the locals rename report stayed green, and `ghidra_projects/xzre_ghidra_portable.zip` refreshed with the updated project snapshot.
- Next: continue the LR4 backlog (e.g., mirror the new locals/inline coverage into `backdoor_init_stage2` or pick up the pending struct tracker work once the loader batch is fully refreshed).

## 2025-11-25
- Session `SR2` follow-up: revisited `sshd_find_sensitive_data`, renamed the lingering digest/libcrypto/segment temps via `metadata/xzre_locals.json`, expanded its plate text, and added inline comments for the secret-data batch zeroization, `.data` span capture, CET-aware `find_function` bounds, and candidate-selection threshold.
- Ran `./scripts/refresh_xzre_project.sh` after editing the metadata so the regenerated `xzregh/105410_sshd_find_sensitive_data.c`, the headless project, locals rename report, and portable archive all include the new names/comments.
- Next: continue tightening the sshd recon batch (e.g., revisit `sshd_get_sensitive_data_score` for the scoring threshold docs) once higher-priority struct work is complete.

## 2025-11-25
- Session `SR3` follow-up: revisited `process_is_sshd`, renamed the lingering `EVar3`/`.data` padding temps via `metadata/xzre_locals.json`, expanded its plate text, and added inline comments covering the stack_end guard, argv count filter, envp NULL rejection, and `.bss` padding headroom rule.
- Ran `./scripts/refresh_xzre_project.sh` after the metadata edits so `xzregh/103A20_process_is_sshd.c`, the headless project, the locals rename report, and the portable archive absorbed the new names/comments.
- Next: keep iterating on the SR3 backlog (e.g., mirror the new env/stack guard inline detail into the neighbouring sshd recon helpers) or pivot to the struct tracker if that becomes higher priority.

## 2025-11-25
- Session `CC5`: documented `secret_data_append_from_address`, `_from_call_site`, and `_items`; renamed their lingering register temps (`code_pointer`, `caller_return_address`, `descriptor`, `ordinal_cursor`, etc.) in `metadata/xzre_locals.json`, and promoted each AutoDoc to plate+inline form so the sentinel handling, unaff_retaddr hop, and batch walker semantics read clearly inside `xzregh/10AB9*/10ABC0/10ABE0`.
- Ran `./scripts/refresh_xzre_project.sh` twice to land the new inline match strings; the second pass finished cleanly (inline comments present, locals rename report still green, portable archive refreshed) after the initial substring tweaks.
- Next: with the crypto_cmd batch completed, pivot to the struct tracker (e.g., `sshd_payload_ctx_t` in `docs/STRUCT_PROGRESS.md`) unless another function session takes priority.
- Session `CC4`: deep-reviewed `get_string_id` plus the secret-data append helpers (`secret_data_append_from_instruction`, `_from_code`, `_singleton`, `_item`); renamed their register temps (`child_entry`/`child_rank`, `bit_slot`, `ctx_wipe_cursor`, `cursor_work`, `shared_ctx_addr`, etc.) in `metadata/xzre_locals.json`, and promoted each AutoDoc entry to plate+inline form so the trie bitmap math, opcode filters, CALL-skipping sweep, singleton guard bytes, and descriptor short-circuit behaviour are documented directly in `xzregh/*.c`.
- Ran `./scripts/refresh_xzre_project.sh` once the metadata settled; the regenerated Ghidra project, `xzregh/10A88*`/`10A99*`/`10AA*`/`10AB70` sources, locals rename report, and `ghidra_projects/xzre_ghidra_portable.zip` all updated cleanly with the new inline comments and names.
- Next: close out the crypto batch with session `CC5` (the address/call-site append helpers) so every secret-data builder shares the same locals and inline documentation before circling back to the remaining backlog items.

## 2025-11-24
- Session `CC3`: deep-reviewed `run_backdoor_commands`, the RSA hook wrappers, and `count_bits`; renamed the do-orig/control flag temps via `metadata/xzre_locals.json`, converted their AutoDocs to plate+inline form, and added inline anchors covering the opcode dispatch (log/PAM toggles, socket plumbing, sshd_proxy_elevate) plus the hook short-circuit/wrap behaviour so the exported C explains how the dispatcher decides when to fall back to OpenSSL.
- Ran `./scripts/refresh_xzre_project.sh` twice while fixing inline match strings; the final pass refreshed `xzregh/`, the portable archive, and the locals rename report with no warnings.
- Next: move on to session `CC4` (secret-data appenders I) so the remaining crypto helpers inherit the same locals + inline coverage before finishing the command channel batch.

## 2025-11-24
- Session `CC2`: reviewed `verify_signature`, `sshd_get_sshbuf`, `sshbuf_bignum_is_negative`, `sshbuf_extract`, and `secret_data_get_decrypted`; renamed their lingering scratch locals (`wipe_cursor`, `pkex_entry_span`, `banner_hits`, `payload_offset`, `sshbuf_span`, `seed_key_buf`, etc.) and promoted each metadata entry to plate+inline form so the sha256 splice/Ed448 verify, pkex brute-force heuristics, MSB scan, dynamic sshbuf layout, and two-stage ChaCha decrypt are documented directly in the decomp.
- Ran `./scripts/refresh_xzre_project.sh` multiple times while fixing inline match strings and reverting a locals rename that clobbered `seed_iv`; the final pass completed cleanly (rename report green, portable archive refreshed) with only the longstanding `piVar2` warning noted by postprocess.
- Next: move on to session `CC3` (RSA hook wrappers) so the rest of the crypto helpers pick up the same locals/inline coverage before diving into the appenders.

## 2025-11-24
- Session `CC1`: reviewed `dsa_key_hash`, `chacha_decrypt`, `sha256`, `bignum_serialize`, and `rsa_key_hash`; renamed their lingering locals/register temps (`fingerprint_stream`, `wipe_words`, `bytes_written`, `fingerprint_bytes`, etc.) and promoted each AutoDoc to plate+inline form so the zeroization passes, import guards, serialization loops, and sha256 hand-offs are documented directly in the decomp.
- Ran `./scripts/refresh_xzre_project.sh` repeatedly while fixing a JSON escape and a few inline match strings; final pass completed cleanly (no warnings, rename report stayed green, portable archive refreshed, inline comments landed in `xzregh/*`).
- Next: move on to session `CC2` (verify_signature + sshbuf helpers + secret_data_get_decrypted) so the rest of the crypto stack gains the same locals/inline coverage before diving into the RSA hook wrappers.

## 2025-11-24
- Session `LR6`: reviewed `c_strlen`, `c_strnlen`, `fd_read`, `fd_write`, and `contains_null_pointers`; renamed their lingering `len`/`slot`/`count` register temps (`bytes_counted`, `bytes_checked`, `chunk_size`, `bytes_left`, `candidate_slot`, etc.), converted their metadata entries to plate+inline form, and added inline anchors covering the fast-path exits, EINTR retry loops, and NULL-pointer checks.
- Ran `./scripts/refresh_xzre_project.sh` once the metadata settled; the locals rename report stayed green, `xzregh/*.c` picked up the inline comments/new names, and the portable archive refreshed without warnings.
- Next: pivot into `CC1` (crypto primitives) so the first crypto batch gains the same locals + inline coverage before digging into the secret-data appenders.

## 2025-11-24
- Session `LR5`: reviewed `backdoor_entry`, `_get_cpuid_modified`, `_cpuid_gcc`, and `count_pointers` (plus re-verified `xzre_globals`); renamed the cpuid scratch registers and pointer counters in `metadata/xzre_locals.json`, promoted their AutoDocs to plate+inline form, and added inline anchors for the resolver gating, cpuid fallback, and pointer-table heuristics.
- Ran `./scripts/refresh_xzre_project.sh` repeatedly while fixing an inline match and converting the new AutoDoc text to ASCII; final pass completed cleanly (rename report stayed green, inline comments landed, portable archive refreshed).
- Next: move into session `LR6` (c stdlib + IO helpers) so the last loader/runtime exports have the same locals/inline coverage before pivoting to the crypto batches.

## 2025-11-24
- Session `LR4`: reviewed `find_link_map_l_audit_any_plt`, `find_dl_audit_offsets`, `backdoor_setup`, `backdoor_init_stage2`, and `backdoor_init`; renamed the lingering register temps (decoder wipes, libcrypto basename buffer, audit bit toggles, cpuid slot pointers), promoted each AutoDoc to plate+inline form, and dropped new inline anchors for the `_dl_audit_symbind_alt` sweep, ld.so offset hunt, GOT sanity gate, secret_data telemetry, and stage-two cpuid patch.
- Ran `./scripts/refresh_xzre_project.sh` twice (fixing inline match strings) until `xzregh/`, the locals rename report, and `ghidra_projects/xzre_ghidra_portable.zip` all reflected the new metadata with no warnings.
- Next: start session `LR5` (backdoor entry/cpuid helpers + globals) so the remaining loader/runtime exports have the same locals + inline coverage.

## 2025-11-24
- Session `LR3`: deep-reviewed `find_dl_naudit`, `resolve_libc_imports`, `process_shared_libraries_map`, `process_shared_libraries`, and `find_link_map_l_audit_any_plt_bitmask`; promoted their AutoDocs to plate+inline form, renamed the MOV/slot/SONAME trackers in `metadata/xzre_locals.json`, and added inline anchors for the GLRO literal hunt, libc trampoline allocations, SONAME hashing, `_r_debug` scratch copy, and audit-bit state machine.
- Ran `./scripts/refresh_xzre_project.sh` (twice while iterating on inline matches) until the regenerated `xzregh/*.c`, locals rename report, and portable archive picked up the new comments without warnings.
- Next: move on to session `LR4` (audit offsets + stage-two setup) so the remainder of the loader helpers share the same docs/locals coverage.

## 2025-11-24
- Session `LR2`: reviewed `update_cpuid_got_index`, `get_tls_get_addr_random_symbol_got_offset`, `update_got_address`, `update_got_offset`, and `find_link_map_l_name`; renamed the GOT math temps (plt stub, disp offset, runtime map trackers), added the missing inline AutoDoc anchors (sentinel GOT seed, long/short JMP handling, RELRO + dual-LEA checks), and refreshed `metadata/functions_autodoc.json` / `metadata/xzre_locals.json` accordingly.
- Ran `./scripts/refresh_xzre_project.sh` after each metadata tweak until the inline matcher landed cleanly (no warnings, rename report stayed green) and the regenerated `xzregh/*.c` / portable archive picked up the new comments.
- Updated `docs/FUNCTION_PROGRESS.md` to mark LR2 complete.
- Next: continue into session `LR3` (link-map walks and libc import wiring) so the rest of the loader helpers have the same locals + inline coverage.

## 2025-11-24
- Session `LR1`: reviewed `init_ldso_ctx`, `init_hooks_ctx`, `init_shared_globals`, `init_imported_funcs`, and `validate_log_handler_pointers`; renamed the bindflag/audit/log-handler temps in `metadata/xzre_locals.json`, promoted all five AutoDocs to `plate+inline` form (covering the ld.so reset, hook-publishing retries, shared-global wiring, libcrypto import sanity checks, and the MOV/LEA validator), and reran `./scripts/refresh_xzre_project.sh` so xzregh/`ghidra_projects/xzre_ghidra_portable.zip` picked up the locals + inline comments (rename report stayed clean).
- Next: proceed with session `LR2` (GOT math + symbol resolution) so the remaining loader helpers gain the same locals/inline coverage before pivoting deeper into the runtime batches.

## 2025-11-24
- Session `SR5`: finished the monitor message hook batch (`mm_answer_keyverify_hook`, `mm_answer_authpassword_hook`, `mm_answer_keyallowed_hook`, `mm_log_handler_hook`, `decrypt_payload_message`) by promoting each AutoDoc to plate+inline form with literal anchors, renaming the lingering register temps (`sshd_ctx`, payload seed/header buffers, log rewrite fragments), and refreshing the metadata-driven inline comments. `metadata/functions_autodoc.json` now fully documents the payload state machine plus the log filter rewrites, and `metadata/xzre_locals.json` maps every temp so `xzregh/*.c` mirrors the Ghidra locals.
- Reran `./scripts/refresh_xzre_project.sh` until the locals rename report stayed clean, the regenerated `xzregh` sources picked up the inline notes, and the portable project archive was refreshed for the new metadata.
- Next: pivot to the loader batch (`LR1`) so the init/import helpers receive the same locals + inline coverage before circling back to any remaining sshd recon edge cases.

## 2025-11-24
- Session `SR4`: deep-reviewed `sshd_patch_variables`, `sshd_configure_log_hook`, `check_backdoor_state`, `extract_payload_message`, and `sshd_proxy_elevate`; renamed the lingering register temps for the monitor/PAM toggles, sshbuf parser, and proxy elevater; upgraded each AutoDoc entry to `plate+inline` form with new match anchors; and reran `./scripts/refresh_xzre_project.sh` twice to land the metadata (locals, inline comments, portable archive, rename report stayed clean).
- Next: roll into session `SR5` (monitor message hooks) so the remaining sshd recon exports inherit the same locals + inline coverage before pivoting to the loader batches.

## 2025-11-24
- Session `SR3`: deep-reviewed `check_argument`, `process_is_sshd`, `sshd_log`, `sshd_get_usable_socket`, and `sshd_get_client_socket`; renamed their lingering `lVar*/puVar*/sockfd_*` temps via `metadata/xzre_locals.json`, upgraded each AutoDoc to `plate+inline` form (covering the dash filter, stack/env vetting, sshlogv wrapper, fd probe, and monitor fallback), and reran `./scripts/refresh_xzre_project.sh` twice until the inline matches stuck and the locals rename report stayed clean. Updated FUNCTION_PROGRESS for SR3.
- Next: move on to session `SR4` (monitor patch/log hook/payload path) now that the process vetting + socket plumbing helpers are documented.

## 2025-11-24
- Session `SR2`: deep-reviewed the score aggregation helpers, monitor vote collector, and `sshd_find_sensitive_data`, renamed their lingering `BVar*/uVar*/p*` temps in `metadata/xzre_locals.json`, promoted each AutoDoc entry to `plate+inline` form (covering the voting math, heuristics, and libcrypto bootstrap), and reran `./scripts/refresh_xzre_project.sh` twice while fixing inline match strings so `xzregh/`, the Ghidra project, locals report, and the portable archive all reflect the new annotations with no warnings.
- Next: move on to session `SR3` to finish documenting the remaining sshd monitor helpers and hook plumbing before pivoting to the loader/runtime batches.

## 2025-11-24
- Session `SR1`: reviewed the sshd entrypoint/sensitive-data helpers (`sshd_find_main`, monitor-field finder, the `KRB5CCNAME` and xcalloc heuristics, plus the `do_child` scorer), renamed their remaining register temps in `metadata/xzre_locals.json`, promoted each AutoDoc to `plate+inline` form with new inline comment anchors, and reran `./scripts/refresh_xzre_project.sh` multiple times while iterating on the regex matches until the inline injection finished cleanly (locals rename report stayed green, `xzregh/*.c` + portable archive regenerated).
- Next: move on to session `SR2` (score aggregation and monitor discovery) so the rest of the sshd-sensitive-data pipeline carries the same locals/inline coverage before diving into the hook plumbing.

## 2025-11-24
- Session `EL6`: wrapped `get_lzma_allocator` by promoting its AutoDoc entry to a `plate+inline` block, renaming the lone register temp to `fake_allocator` in `metadata/xzre_locals.json`, and re-running `./scripts/refresh_xzre_project.sh` so the inline comments and locals rewrite landed in `xzregh/104060_get_lzma_allocator.c`, the Ghidra project, and the portable archive (locals rename report stayed clean).
- Next: pivot into `sshd_recon` session `SR1` now that the ELF helpers are fully documented.

## 2025-11-23
- Session `EL5`: tackled `j_tls_get_addr`, the allocator/vtable address helpers, `main_elf_parse`, and `init_elf_entry_ctx`—added the missing `register_temps` entry for the TLS wrapper, promoted each AutoDoc to a `plate+inline` description (covering the sentinel walks, ld.so verification path, and cpuid GOT prep), dropped inline comments into the exported C, and reran `./scripts/refresh_xzre_project.sh` twice (to fix an inline placement) so Ghidra/xzregh/`xzre_ghidra_portable.zip` reflect the new metadata with a clean locals-rename report.
- Next: close out `elf_mem` with session `EL6` (`get_lzma_allocator`) so every ELF helper has the same locals/inline coverage before pivoting to the sshd discovery batches.

## 2025-11-23
- Session `EL4`: deep-dived `elf_get_rodata_segment`, `elf_find_string`, `elf_get_data_segment`, `elf_contains_vaddr_relro`, and `is_range_mapped`—renamed their register temps in `metadata/xzre_locals.json`, promoted each AutoDoc to `plate+inline` form (documenting the telemetry gates, PF_R/PF_W sweeps, RELRO clamp, and the `pselect`-based range probe), and reran `./scripts/refresh_xzre_project.sh` twice to land the new inline comments in `xzregh/*`, refresh the portable archive, and keep the locals rename report clean.
- Next: start session `EL5` (TLS + allocator wrappers) so the remaining ELF utilities carry the same level of locals/inline coverage before pivoting to sshd-recon work.

## 2025-11-23
- Session `EL3`: reversed `elf_find_relr_reloc`, `elf_get_reloc_symbol`, `elf_get_{plt,got}_symbol`, and `elf_get_code_segment` by renaming the RELR slot/bounds/resume temps plus the PLT/GOT scratch pointers in `metadata/xzre_locals.json`, promoting their AutoDocs to `plate+inline` form (telemetry breadcrumbs, literal-vs-bitmap decoding, relocation filters, text-segment caching/alignment), and rerunning `./scripts/refresh_xzre_project.sh` twice so the regenerated `xzregh/*.c`, locals report, and portable archive all picked up the new inline matches without warnings.
- Next: start session `EL4` (segment/string queries) so the remaining ELF walkers match the same level of locals + inline coverage before pivoting to sshd work.

## 2025-11-23
- Session `EL2`: deep-dived `elf_symbol_get[*]`, `c_memmove`, `fake_lzma_alloc`, and `elf_find_rela_reloc`; renamed the GNU-hash/versym/reloc cursors plus the allocator shims in `metadata/xzre_locals.json`, converted the AutoDoc entries to `plate+inline` form (telemetry breadcrumbs, symbol-definition filters, version walks, allocator reinterpretation, RELA range gating), and fixed the `elf_find_rela_reloc` prototype to expose the `[low, high]` pointer window. Ran `./scripts/refresh_xzre_project.sh` (three passes while iterating on inline matches) so the Ghidra project, `xzregh/*.c`, locals report, and portable archive picked up the new names/comments without diffs.
- Next: start session `EL3` (RELR/GOT walkers) so the relocation helpers share the same level of locals + inline coverage before pivoting to `sshd_recon`.

## 2025-11-23
- Session `EL1`: reviewed `fake_lzma_free`, the `elf_contains_vaddr*` helpers, `is_gnu_relro`, and `elf_parse`; renamed the ambiguous register temps (recursion depth/page windows/program-header cursors) plus the struct-wipe pointer in `metadata/xzre_locals.json`, upgraded every AutoDoc entry to `plate+inline` form, and threaded inline comments through the exported C so the struct wipe, PT_DYNAMIC validation, RELRO obfuscation, and range-splitting behavior are obvious in `xzregh/*.c`. Ran `./scripts/refresh_xzre_project.sh` to sync the metadata into the headless project/exported sources and updated FUNCTION_PROGRESS accordingly (locals rename report remained clean).
- Next: move to `EL2` (symbol + allocator priming) so the rest of the ELF utilities have the same locals/inline coverage before diving into the sshd discovery batches.

## 2025-11-23
- Session `JMP-cleanup`: added `scripts/remove_hook_jumptable_warnings.py` plus a new refresh step so the exported hook wrappers automatically replace Ghidra’s false “Could not recover jumptable” warnings with an inline explanation of the tail-call back into the preserved OpenSSL/mm handlers; reran `./scripts/refresh_xzre_project.sh` so the change propagated into `xzregh/*.c`, the portable archive, and the rename/rodata outputs (rename report stayed green).
- Next: extend the helper if any other hook wrappers pick up the same warning pattern, or revisit this once Ghidra exposes a knob to suppress the indirect-jump detection without post-processing.

## 2025-11-23
- Session `EL6-cleanup`: deleted the four trap-only exports (`lzma_check_init`, `__tls_get_addr`, `lzma_free`, `lzma_alloc`) from `xzregh/`, scrubbed their AutoDoc/locals/function-progress metadata, and taught `ExportFunctionDecompilations.py` to skip them so the next refresh no longer recreates empty bodies. Added the upstream liblzma headers (`src/liblzma/check/check.h`, `src/liblzma/common/common.h`, plus the shared tuklib/mythread/sysdefs includes) and glibc’s `dl-tls.h` under `third_party/include/` so the real prototypes live beside the rest of the vendor headers, then double-checked the call sites (e.g., `backdoor_init_stage2`, allocator shims, `j_tls_get_addr`) still compile via the existing declarations in `metadata/xzre_types.json`.
- Next: run `./scripts/refresh_xzre_project.sh --check-only` to verify the skip list behaves as expected and reconcile any newly unmapped prototypes with the fresh third-party headers.

## 2025-11-23
- Session `OP4`: reversed `elf_find_function_pointer`, `elf_find_string_references`, and `elf_find_string_reference` by renaming the slot/range/xref register temps in `metadata/xzre_locals.json`, upgrading their AutoDocs to full `plate+inline` entries, and adding inline comment placements that explain the RELA/RELR hunt plus the rodata/text sweeps. Ran `./scripts/refresh_xzre_project.sh` so the metadata synced into Ghidra/xzregh, verified the inline comments injected correctly, and updated FUNCTION_PROGRESS/notes (locals rename report stayed clean).
- Next: start `EL1` (ELF containment + parser entry) now that the opcode batch is wrapped and the string catalogue helpers are documented.

## 2025-11-22
- Session `OP3`: renamed the decoder scratch temps across the string/MOV/ADD helpers, expanded each AutoDoc (plus inline comments) to explain the instrumentation, sliding-window predicate, and RIP-relative range tests, and reran `./scripts/refresh_xzre_project.sh` twice so the inline injection finished cleanly (locals rename report stayed green).
- Next: roll the same treatment into `OP4` (ELF pointer & string crossovers) now that the memory-operand sweepers are documented.

## 2025-11-21
- Inline AutoDocs: taught `metadata/functions_autodoc.json` to store `plate` + `inline` blocks, updated the Ghidra scripts/export helpers to understand the new format, extended `apply_ghidra_comments_to_decomp.py` to inject `// AutoDoc:` inline notes, wired the refresh pipeline to feed the metadata into that script, and re-ran `./scripts/refresh_xzre_project.sh` so the exported `xzregh/*.c` now pick up the metadata-driven inline comments automatically.
- Next: migrate any remaining hand-written inline notes into `metadata/functions_autodoc.json` so future refreshes keep them stable, then continue OP3 work.

## 2025-11-21
- Function sessions `OP1`/`OP2`: threaded inline comments through the exported decomp (`x86_dasm`, CET prologue scanners, MOV/LEA/MOV+call helpers, and the reg↔reg predicate) so the telemetry hooks, context wipes, and opcode filters are explained in-line for anyone triaging the opcode utilities from the text dumps.
- Next: if we need these annotations to survive future refreshes, mirror the same commentary into `metadata/functions_autodoc.json` (or extend the metadata format to allow inline placements) before rerunning `./scripts/refresh_xzre_project.sh`.

## 2025-11-21
- Authored the missing `xzre_globals` AutoDoc so the headless refresh stops complaining about the shared hooks blob; updated notes/progress metadata and reran the helper to keep the data symbol documented as the canonical runtime snapshot (`ldso_ctx_t`, `global_ctx`, resolved imports, payload buffers).
- Next: confirm the next refresh run reports a clean AutoDoc delta now that the blob is documented, then resume OP3 work.

## 2025-11-21
- Function session `OP2`: documented the MOV/LEA scanners and the register-only predicate, renamed every scratch decoder temp in `metadata/xzre_locals.json`, refreshed the notes/progress tracker, and reran `./scripts/refresh_xzre_project.sh` so xzregh plus the portable archive show the new AutoDocs/locals (rename report stayed clean; only the long-standing `xzre_globals` AutoDoc delta remains).
- Next: roll the same treatment into `OP3` (memory operand sweeps) or finally author the missing `xzre_globals` AutoDoc so the refresh warning disappears.

## 2025-11-21
- `find_function`: taught the metadata locals pass about the scratch output array (`prologue_result`) so `local_40` is now renamed via `register_temps`; reran `./scripts/refresh_xzre_project.sh` to propagate the change and confirm the rename report stays clean.
- Next: consider whether `find_function_prologue` needs a similar treatment for the nested pointer window before moving deeper into OP2.

## 2025-11-21
- Function session `OP1`: expanded the AutoDoc copy for `x86_dasm`, `is_endbr64_instruction`, `find_function_prologue`, `find_function`, and `find_call_instruction`, renamed the decoder/modrm/immediate temps plus the scratch ctx zeroing variables in `metadata/xzre_locals.json`, updated `docs/FUNCTION_PROGRESS.md`, and reran `./scripts/refresh_xzre_project.sh` so xzregh + the portable archive reflect the changes (locals rename report stayed clean despite multiple reruns while iterating on the find_function scratch array).
- Next: roll the same treatment into `OP2` (MOV/LEA scanners) and see if we can replace the remaining `local_40` pointer array in `find_function` with a properly named helper once we understand how Ghidra models that stack slot.

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
# Progress Log
