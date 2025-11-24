# Function Reverse-Engineering Progress

Track deep-dives on exported functions the same way we do for structs. Work a five-function session, summarize what changed in metadata/notes, and bump the counter below so the next analyst knows where to focus. The batch groupings mirror AGENTS.md but shrink to roughly five related functions per session so you can queue smaller RE bursts.

## Workflow Notes

- Generate or refresh notes under `notes/` as you walk each session, then promote final names/comments into `metadata/functions_autodoc.json` and `metadata/xzre_locals.json`.
- Run `./scripts/refresh_xzre_project.sh` (or `--check-only`) after editing metadata so Ghidra/xzregh stay aligned.
- Log milestones in `PROGRESS.md` and cite the session ID so others can pick up the thread.
- Increment the `Review Count` for every function you materially improved; use the `Notes` column to summarize scope/date.

## Recommended Function Review Order

Each table below lists five-function sessions in the order we recommend tackling them. The final session in a category may contain fewer entries when the batch size is not divisible by five.

### Opcode Scanners & Pattern Utilities (`opco_patt`)

_Walk the x86 helpers first so every later pass can lean on consistent pattern-matching primitives._

| Session | Focus | Functions |
| --- | --- | --- |
| `OP1` | Decoder & entry markers | `100020_x86_dasm`, `100AC0_is_endbr64_instruction`, `100B10_find_function_prologue`, `100BA0_find_function`, `100C90_find_call_instruction` |
| `OP2` | MOV/LEA pattern search | `100D40_find_mov_lea_instruction`, `100E00_find_mov_instruction`, `100EB0_find_lea_instruction`, `100F60_find_lea_instruction_with_mem_operand`, `10AC40_find_reg2reg_instruction` |
| `OP3` | Memory operand sweeps | `101020_find_string_reference`, `101060_find_instruction_with_mem_operand_ex`, `101120_find_instruction_with_mem_operand`, `101170_find_add_instruction_with_mem_operand`, `102C60_find_addr_referenced_in_mov_instruction` |
| `OP4` | ELF pointer & string crossovers | `102A50_elf_find_function_pointer`, `102D30_elf_find_string_references`, `1032C0_elf_find_string_reference` |

### ELF Introspection & Memory Utilities (`elf_mem`)

_Tackle the ELF walkers from containment → relocations → allocator/tls glue._

| Session | Focus | Functions |
| --- | --- | --- |
| `EL1` | Containment + parser entry | `101210_fake_lzma_free`, `101240_elf_contains_vaddr_impl`, `1013A0_elf_contains_vaddr`, `1013B0_is_gnu_relro`, `1013D0_elf_parse` |
| `EL2` | Symbol + allocator priming | `101880_elf_symbol_get`, `101B00_elf_symbol_get_addr`, `101B30_c_memmove`, `101B80_fake_lzma_alloc`, `101B90_elf_find_rela_reloc` |
| `EL3` | Reloc walkers | `101C30_elf_find_relr_reloc`, `101DC0_elf_get_reloc_symbol`, `101E60_elf_get_plt_symbol`, `101E90_elf_get_got_symbol`, `101EC0_elf_get_code_segment` |
| `EL4` | Segment/string queries | `101F70_elf_get_rodata_segment`, `1020A0_elf_find_string`, `102150_elf_get_data_segment`, `1022D0_elf_contains_vaddr_relro`, `102370_is_range_mapped` |
| `EL5` | TLS + function lookup | `102440_j_tls_get_addr`, `102490_get_lzma_allocator_address`, `1024F0_get_elf_functions_address`, `103CE0_main_elf_parse`, `104030_init_elf_entry_ctx` |
| `EL6` | Allocator/tls wrappers | `104060_get_lzma_allocator` |

### SSHD Discovery & Sensitive Data Recon (`sshd_recon`)

_Progress from finding sshd to wiring in the mm hooks and decrypting payloads._

| Session | Focus | Functions |
| --- | --- | --- |
| `SR1` | Entry points & monitor fields | `102550_sshd_find_main`, `102FF0_sshd_find_monitor_field_addr_in_function`, `103340_sshd_get_sensitive_data_address_via_krb5ccname`, `103680_sshd_get_sensitive_data_address_via_xcalloc`, `103870_sshd_get_sensitive_data_score_in_do_child` |
| `SR2` | Score aggregation + monitor discovery | `103910_sshd_get_sensitive_data_score_in_main`, `103990_sshd_get_sensitive_data_score_in_demote_sensitive_data`, `103D50_sshd_get_sensitive_data_score`, `103DB0_sshd_find_monitor_struct`, `105410_sshd_find_sensitive_data` |
| `SR3` | Process vetting & socket plumbing | `1039C0_check_argument`, `103A20_process_is_sshd`, `107400_sshd_log`, `107BC0_sshd_get_usable_socket`, `107C60_sshd_get_client_socket` |
| `SR4` | Runtime patching & payload flow | `107D50_sshd_patch_variables`, `107DE0_sshd_configure_log_hook`, `107EA0_check_backdoor_state`, `107F20_extract_payload_message`, `108270_sshd_proxy_elevate` |
| `SR5` | Monitor message hooks | `108080_mm_answer_keyverify_hook`, `108100_mm_answer_authpassword_hook`, `108EA0_mm_answer_keyallowed_hook`, `10A3A0_mm_log_handler_hook`, `108D50_decrypt_payload_message` |

### Loader Hooks & Runtime Setup (`loader_rt`)

_Cover initialization, GOT math, link-map audits, then finish with runtime helpers._

| Session | Focus | Functions |
| --- | --- | --- |
| `LR1` | Init contexts & imports | `102770_init_ldso_ctx`, `1027D0_init_hooks_ctx`, `102850_init_shared_globals`, `102890_init_imported_funcs`, `102B10_validate_log_handler_pointers` |
| `LR2` | GOT math & symbol resolution | `103F60_update_cpuid_got_index`, `103F80_get_tls_get_addr_random_symbol_got_offset`, `103FA0_update_got_address`, `104010_update_got_offset`, `104080_find_link_map_l_name` |
| `LR3` | Link-map walks | `104370_find_dl_naudit`, `1045E0_resolve_libc_imports`, `104660_process_shared_libraries_map`, `104A40_process_shared_libraries`, `104AE0_find_link_map_l_audit_any_plt_bitmask` |
| `LR4` | Audit offsets & stage two | `104EE0_find_link_map_l_audit_any_plt`, `1051E0_find_dl_audit_offsets`, `105830_backdoor_setup`, `106F30_backdoor_init_stage2`, `10A794_backdoor_init` |
| `LR5` | Entry + cpuid adaptations | `10A720_backdoor_entry`, `10A800_get_cpuid_modified`, `10A700_cpuid_gcc`, `1074B0_count_pointers`, `xzre_globals` |
| `LR6` | C stdlib + IO helpers | `107030_c_strlen`, `107050_c_strnlen`, `107080_fd_read`, `1070F0_fd_write`, `107170_contains_null_pointers` |

### Crypto, Secret Data & Command Channel (`crypto_cmd`)

_Work from crypto primitives forward into the secret-data builders._

| Session | Focus | Functions |
| --- | --- | --- |
| `CC1` | Crypto primitives | `103B80_dsa_key_hash`, `107190_chacha_decrypt`, `1072B0_sha256`, `107320_bignum_serialize`, `107510_rsa_key_hash` |
| `CC2` | Signature checks & sshbuf helpers | `107630_verify_signature`, `107A20_sshd_get_sshbuf`, `107920_sshbuf_bignum_is_negative`, `107950_sshbuf_extract`, `1081D0_secret_data_get_decrypted` |
| `CC3` | Backdoor RSA hooks | `1094A0_run_backdoor_commands`, `10A240_hook_RSA_public_decrypt`, `10A2D0_hook_EVP_PKEY_set1_RSA`, `10A330_hook_RSA_get0_key`, `10A860_count_bits` |
| `CC4` | Secret data appenders I | `10A880_get_string_id`, `10A990_secret_data_append_from_instruction`, `10AA00_secret_data_append_from_code`, `10AAC0_secret_data_append_singleton`, `10AB70_secret_data_append_item` |
| `CC5` | Secret data appenders II | `10AB90_secret_data_append_from_address`, `10ABC0_secret_data_append_from_call_site`, `10ABE0_secret_data_append_items` |

## Function Progress Tracker

Update this table whenever you finish a session. Keep the latest pass at the top of each note so new work is easy to skim.

| Function | Batch | Review Count | Notes |
| --- | --- | --- | --- |
| `100020_x86_dasm` | `opco_patt` | 1 | 2025-11-21 (OP1) – expanded AutoDoc and renamed the imm/modrm helpers so the decoder locals read cleanly. |
| `100AC0_is_endbr64_instruction` | `opco_patt` | 1 | 2025-11-21 (OP1) – clarified the CET mask semantics and renamed the single bool to `has_endbr`. |
| `100B10_find_function_prologue` | `opco_patt` | 1 | 2025-11-21 (OP1) – documented the ENDBR+alignment path and retagged the ctx zeroing cursor. |
| `100BA0_find_function` | `opco_patt` | 1 | 2025-11-21 (OP1) – refreshed the backward/forward scan summary; `local_40` scratch still needs a future rename. |
| `100C90_find_call_instruction` | `opco_patt` | 1 | 2025-11-21 (OP1) – wrote up the telemetry+call-target logic and renamed the scratch ctx zeroing temps. |
| `100D40_find_mov_lea_instruction` | `opco_patt` | 1 | 2025-11-21 (OP2) – Documented the hybrid MOV/LEA filter, tied AutoDoc to the load/store + REX.W checks, and renamed the scratch decoder zeroing temps (`ctx_clear_idx/cursor`, `decoded_opcode`, `is_expected_opcode`). |
| `100E00_find_mov_instruction` | `opco_patt` | 1 | 2025-11-21 (OP2) – MOV-only path now describes the byte-by-byte retry behaviour, enforces the load/store width constraint in doc, and adopts the same ctx zeroing/local names as the other pointer scanners. |
| `100EB0_find_lea_instruction` | `opco_patt` | 1 | 2025-11-21 (OP2) – Added the secret-data breadcrumb + ±displacement explanation and renamed the stack decoder wipe loop (`ctx_clear_idx/cursor`, `ctx_stride_sign`). |
| `100F60_find_lea_instruction_with_mem_operand` | `opco_patt` | 1 | 2025-11-21 (OP2) – Clarified the optional RIP target comparison, the REX.W+ModRM requirements, and synced the scratch ctx locals/notes with the other LEA helpers. |
| `10AC40_find_reg2reg_instruction` | `opco_patt` | 1 | 2025-11-21 (OP2) – Wrote up the ModRM/prefix rejects, documented the arithmetic opcode bitmask, and renamed the temps to `decoded`/`opcode_lookup_index`. |
| `101020_find_string_reference` | `opco_patt` | 1 | 2025-11-22 (OP3) – Named the LEA hit/ctx wipe temps and documented how the helper returns the LEA site as the string xref anchor. |
| `101060_find_instruction_with_mem_operand_ex` | `opco_patt` | 1 | 2025-11-22 (OP3) – Captured the secret-data instrumentation, renamed the ctx stride controls, and added inline notes for the sliding window plus DF2/RIP predicate. |
| `101120_find_instruction_with_mem_operand` | `opco_patt` | 1 | 2025-11-22 (OP3) – Clarified the LEA-vs-MOV handoff and inserted the inline comment that explains why the MOV predicate re-runs with opcode `0x10b`. |
| `101170_find_add_instruction_with_mem_operand` | `opco_patt` | 1 | 2025-11-22 (OP3) – Synced the scratch decoder locals, documented the opcode `0x103` + ModRM requirements, and noted the optional RIP comparison inline. |
| `102C60_find_addr_referenced_in_mov_instruction` | `opco_patt` | 1 | 2025-11-22 (OP3) – Introduced `func_cursor/func_end`, described the 32-bit MOV/DF2 gating, and added inline commentary for the RIP-relative recompute and range test. |
| `102A50_elf_find_function_pointer` | `opco_patt` | 1 | 2025-11-23 (OP4) – Documented the RELA/RELR slot hunt, renamed the slot/xref temps, and annotated the RELRO + ENDBR checks. |
| `102D30_elf_find_string_references` | `opco_patt` | 1 | 2025-11-23 (OP4) – Clarified the catalogue builder loops, renamed the range/xref temps, and added inline notes for the rodata/text/reloc passes. |
| `1032C0_elf_find_string_reference` | `opco_patt` | 1 | 2025-11-23 (OP4) – Captured the telemetry gate + rodata walk, renamed the temps, and documented the LEA search inline. |
| `101210_fake_lzma_free` | `elf_mem` | 1 | 2025-11-23 (EL1) – Clarified the bootstrap stub’s purpose and dropped an inline `return` comment so the fake allocator wiring is obvious. |
| `101240_elf_contains_vaddr_impl` | `elf_mem` | 1 | 2025-11-23 (EL1) – Renamed the recursion-depth/page-window locals and annotated the alignment + range-splitting paths for overlapping segments. |
| `1013A0_elf_contains_vaddr` | `elf_mem` | 1 | 2025-11-23 (EL1) – Documented the wrapper role, added inline telemetry about passing work to the recursive helper, and confirmed the flag semantics. |
| `1013B0_is_gnu_relro` | `elf_mem` | 1 | 2025-11-23 (EL1) – Captured the additive obfuscation for PT_GNU_RELRO and inserted an inline note explaining the wrapped constant. |
| `1013D0_elf_parse` | `elf_mem` | 1 | 2025-11-23 (EL1) – Renamed the program-header/dynamic-scan locals and added inline comments for the struct wipe, PT_DYNAMIC validation, pointer fixups, and relocation rechecks. |
| `101880_elf_symbol_get` | `elf_mem` | 1 | 2025-11-23 (EL2) – renamed the GNU-hash bucket/chain/versym cursors, added telemetry + versym-walk inline comments, and refreshed the exported C so the secret-data breadcrumb plus version gating read clearly. |
| `101B00_elf_symbol_get_addr` | `elf_mem` | 1 | 2025-11-23 (EL2) – collapsed the misnamed temp to `sym_entry`, documented the defined-symbol gate + module-base addition inline, and re-synced the metadata so the stub mirrors `elf_symbol_get`. |
| `101B30_c_memmove` | `elf_mem` | 1 | 2025-11-23 (EL2) – retitled the reverse copy index and injected inline comments that spell out the backward- vs forward-copy paths. |
| `101B80_fake_lzma_alloc` | `elf_mem` | 1 | 2025-11-23 (EL2) – removed the unused locals, renamed the return temp to `symbol_addr`, and annotated that `opaque/size` are just `elf_info_t`+EncodedStringId indirection into `elf_symbol_get_addr`. |
| `101B90_elf_find_rela_reloc` | `elf_mem` | 1 | 2025-11-23 (EL2) – renamed the RELA cursor/resume/range temps, exposed the slot lower-bound parameter, and added inline comments covering the RELATIVE-only filter plus optional `[low, high]`/resume handling. |
| `101C30_elf_find_relr_reloc` | `elf_mem` | 1 | 2025-11-23 (EL3) – renamed the RELR slot/bounds/resume temps and added inline comments for the literal vs. bitmap decoding paths plus the optional clamp. |
| `101DC0_elf_get_reloc_symbol` | `elf_mem` | 1 | 2025-11-23 (EL3) – documented the telemetry gate + undefined-symbol filter inline so the relocation sweep logic and writable-slot return path read clearly. |
| `101E60_elf_get_plt_symbol` | `elf_mem` | 1 | 2025-11-23 (EL3) – captured the PLT feature-bit guard and the hand-off into `elf_get_reloc_symbol` (R_X86_64_JUMP_SLOT) with inline notes; renamed the scratch slot pointer. |
| `101E90_elf_get_got_symbol` | `elf_mem` | 1 | 2025-11-23 (EL3) – mirrored the RELA feature-bit requirements and inline commentary for the GOT flow (R_X86_64_GLOB_DAT) plus the slot temp rename. |
| `101EC0_elf_get_code_segment` | `elf_mem` | 1 | 2025-11-23 (EL3) – expanded the AutoDoc/inline notes around the telemetry breadcrumb, `.text` caching, and PT_LOAD alignment maths so the locals explain why the scan only runs once. |
| `101F70_elf_get_rodata_segment` | `elf_mem` | 1 | 2025-11-23 (EL4) – documented the secret-data gate and rodata caching, renamed the rodata cursor/size temps, and added inline breadcrumbs for the cache short-circuit plus the PF_R segment sweep. |
| `1020A0_elf_find_string` | `elf_mem` | 1 | 2025-11-23 (EL4) – captured the `stringId_inOut` semantics, renamed the rodata span buffer, and added inline comments for the telemetry gate, resume pointer clamp, and zero-id fast path. |
| `102150_elf_get_data_segment` | `elf_mem` | 1 | 2025-11-23 (EL4) – renamed the selected-segment locals, expanded the AutoDoc around the PF_W scan + padding math, and annotated the cache hit, segment selection, and alignment branches inline. |
| `1022D0_elf_contains_vaddr_relro` | `elf_mem` | 1 | 2025-11-23 (EL4) – refreshed the RELRO plate to cover the `p_flags` gate, renamed the relro window temps, and injected inline notes for the PF_R check plus the page-aligned RELRO clamp. |
| `102370_is_range_mapped` | `elf_mem` | 1 | 2025-11-23 (EL4) – rewrote the AutoDoc around the `pselect` probe, renamed the libc/import/time cursors, and annotated the low-address guard, import validation, probe call, and EFAULT bailouts inline. |
| `102440_j_tls_get_addr` | `elf_mem` | 1 | 2025-11-23 (EL5) – renamed the lone register temp to `resolved_tls` and documented why this wrapper always jumps straight into glibc’s resolver while the trap stub handles relocations. |
| `102490_get_lzma_allocator_address` | `elf_mem` | 1 | 2025-11-23 (EL5) – spelled out the sentinel+offset trick, renamed the cursor/index temps, and added inline notes for the relocation-safe base pointer and 12-slot walk. |
| `1024F0_get_elf_functions_address` | `elf_mem` | 1 | 2025-11-23 (EL5) – mirrored the relocation-safe pointer math for the helper vtable and annotated the sentinel start plus the 12-slot advance. |
| `103CE0_main_elf_parse` | `elf_mem` | 1 | 2025-11-23 (EL5) – clarified the ld.so parse, `__libc_stack_end` lookup, sshd verification, and pointer publish with inline comments tied to each step. |
| `104030_init_elf_entry_ctx` | `elf_mem` | 1 | 2025-11-23 (EL5) – documented every cpuid GOT prep write (random symbol, resolver-frame slot, GOT math, TLS reset) and added inline breadcrumbs for each field assignment. |
| `104060_get_lzma_allocator` | `elf_mem` | 1 | 2025-11-24 (EL6) – wrapped the helper in a `plate+inline` AutoDoc, renamed `pfVar1` to `fake_allocator` via `metadata/xzre_locals.json`, and reran the refresh so the inline comments/locals rewrite landed in `xzregh/104060_get_lzma_allocator.c`. |
| `102550_sshd_find_main` | `sshd_recon` | 1 | 2025-11-24 (SR1) – Renamed the anonymous ELF symbol temps, documented the allocator/libc bootstrap, and added inline notes for the LEA→`__libc_start_main` pattern so the entry hunt is readable. |
| `102FF0_sshd_find_monitor_field_addr_in_function` | `sshd_recon` | 1 | 2025-11-24 (SR1) – Captured the MOV/LEA seeding flow, the 0x40-byte tracking window, and the RDI→`mm_request_send` requirement via inline comments to make the register chase obvious. |
| `103340_sshd_get_sensitive_data_address_via_krb5ccname` | `sshd_recon` | 1 | 2025-11-24 (SR1) – Expanded the AutoDoc for both getenv/LEA cases, renamed the tracker locals, and annotated the scan/stride math that proves the `.bss` stores. |
| `103680_sshd_get_sensitive_data_address_via_xcalloc` | `sshd_recon` | 1 | 2025-11-24 (SR1) – Clarified how the helper finds the xcalloc call, records each `.bss` store, and tests the ptr/ptr+8/ptr+0x10 triplet, with new inline breadcrumbs on the decoder loop. |
| `103870_sshd_get_sensitive_data_score_in_do_child` | `sshd_recon` | 1 | 2025-11-24 (SR1) – Documented the score math (base + first/second +0x10 hits), renamed the context scratch, and dropped inline notes on each pass over `do_child`. |
| `103910_sshd_get_sensitive_data_score_in_main` | `sshd_recon` | 1 | 2025-11-24 (SR2) – promoted the scoring helper to plate+inline form, renamed the base/+8/+0x10 hit flags, and added inline notes that explain how the signed score is derived. |
| `103990_sshd_get_sensitive_data_score_in_demote_sensitive_data` | `sshd_recon` | 1 | 2025-11-24 (SR2) – captured the single-hit/three-point heuristic in metadata, added inline comments on the string-ref scan, and renamed the demote_hit/score temps. |
| `103D50_sshd_get_sensitive_data_score` | `sshd_recon` | 1 | 2025-11-24 (SR2) – rewrote the aggregator AutoDoc, added inline annotations for each heuristic call, and retitled the `score_*` register temps to match the exported C. |
| `103DB0_sshd_find_monitor_struct` | `sshd_recon` | 1 | 2025-11-24 (SR2) – documented the 10-function vote loop, renamed the candidate/vote cursors, and dropped inline comments describing the counter reuse and ≥5 votes gate. |
| `105410_sshd_find_sensitive_data` | `sshd_recon` | 1 | 2025-11-24 (SR2) – expanded the libcrypto/bootstrap AutoDoc, renamed every `BVar*/uVar*/p*` temp, and added inline notes for the secret-data breadcrumbs, ENDBR64 check, dual heuristics, and cleanup paths. |
| `1039C0_check_argument` | `sshd_recon` | 1 | 2025-11-24 (SR3) – renamed the sliding-window temps, expanded the dash/debug AutoDoc, and added inline comments that explain the exit cases. |
| `103A20_process_is_sshd` | `sshd_recon` | 1 | 2025-11-24 (SR3) – rewrote the stack/argv/env sanity-check AutoDoc, renamed the argv/env cursors, and injected inline notes for each guard. |
| `107400_sshd_log` | `sshd_recon` | 1 | 2025-11-24 (SR3) – documented the SSE save + va_list rebuild, renamed the scratch regs, and added inline comments for the spill/tail-call points. |
| `107BC0_sshd_get_usable_socket` | `sshd_recon` | 1 | 2025-11-24 (SR3) – clarified the shutdown(EINVAL/ENOTCONN) probe, renamed the counter/errno scratch, and annotated the match/return logic inline. |
| `107C60_sshd_get_client_socket` | `sshd_recon` | 1 | 2025-11-24 (SR3) – renamed the monitor/libc pointers, documented the zero-length read probe + fallback, and added inline comments for each branch. |
| `107D50_sshd_patch_variables` | `sshd_recon` | 1 | 2025-11-24 (SR4) – renamed the PermitRootLogin/PAM pointer temps, documented the skip/disable logic inline, and clarified how the monitor_reqtype fallback pulls from the live dispatch slot. |
| `107DE0_sshd_configure_log_hook` | `sshd_recon` | 1 | 2025-11-24 (SR4) – retitled the handler/context slots, added inline notes for the privilege/logging gates, and described the filter-mode string checks before dropping the hook in place. |
| `107EA0_check_backdoor_state` | `sshd_recon` | 1 | 2025-11-24 (SR4) – promoted the state-machine plate to plate+inline, renamed the total-length temp, and annotated the state 0/1/2 window plus the failure reset path. |
| `107F20_extract_payload_message` | `sshd_recon` | 1 | 2025-11-24 (SR4) – renamed the sshbuf cursors and BE length temps, added inline comments for the certificate search and record-length validation, and documented the modulus pointer rewrite. |
| `108270_sshd_proxy_elevate` | `sshd_recon` | 1 | 2025-11-24 (SR4) – renamed the command/import/context temps, added inline notes for the stack-scan/decrypt path, RSA frame forging, socket selection, and the wait/exit reply handling. |
| `108080_mm_answer_keyverify_hook` | `sshd_recon` | 1 | 2025-11-24 (SR5) – documented the staged keyverify reply/dispatch restore, renamed the locals to `sshd_ctx`, and added inline notes for the fd_write/exit guards. |
| `108100_mm_answer_authpassword_hook` | `sshd_recon` | 1 | 2025-11-24 (SR5) – covered both the payload-backed and synthetic reply paths, renamed the sshd_ctx scratch, and dropped inline comments on the fatal guard and slot restore. |
| `108EA0_mm_answer_keyallowed_hook` | `sshd_recon` | 1 | 2025-11-24 (SR5) – expanded the state-machine AutoDoc, added inline comments for the type1/2/3 payload branches plus decrypt/signature checks, and synced the locals metadata. |
| `10A3A0_mm_log_handler_hook` | `sshd_recon` | 1 | 2025-11-24 (SR5) – renamed the log/context fragments, documented the filtering/masking flow, and added inline comments for the Connection closed/Accepted rewrites and syslog toggles. |
| `108D50_decrypt_payload_message` | `sshd_recon` | 1 | 2025-11-24 (SR5) – renamed the ChaCha seed scratch, documented the double-decrypt/copy loop, and added inline comments for the buffer append and payload_state reset. |
| `102770_init_ldso_ctx` | `loader_rt` | 1 | 2025-11-24 (LR1) – renamed the bindflag/audit scratch temps, added inline comments for each reset (`l_name`, auditstate, `_dl_*`), and refreshed the AutoDoc to spell out how ld.so is restored. |
| `1027D0_init_hooks_ctx` | `loader_rt` | 1 | 2025-11-24 (LR1) – retitled the status scratch to `init_status`, documented the hooks_data publication and 0x65 retry semantics, and wired inline notes into the exported C. |
| `102850_init_shared_globals` | `loader_rt` | 1 | 2025-11-24 (LR1) – renamed the status temp, annotated how the shared block publishes the authpassword/RSA hooks + `global_ctx`, and upgraded the AutoDoc to plate+inline form. |
| `102890_init_imported_funcs` | `loader_rt` | 1 | 2025-11-24 (LR1) – promoted the AutoDoc to plate+inline, added commentary around the 0x1d import count gate plus the fallback trampolines, and confirmed the exported C mirrors the metadata. |
| `102B10_validate_log_handler_pointers` | `loader_rt` | 1 | 2025-11-24 (LR1) – renamed the LEA/scan locals (`slot_distance`, `bounded_func_range`, etc.), explained the pointer-gap/LEA/MOV checks inline, and expanded the AutoDoc accordingly. |
| `103F60_update_cpuid_got_index` | `loader_rt` | 1 | 2025-11-24 (LR2) – promoted the AutoDoc to plate+inline form and added the inline note on the relocation constant so the cpuid slot index copy is obvious in `xzregh/103F60`. |
| `103F80_get_tls_get_addr_random_symbol_got_offset` | `loader_rt` | 1 | 2025-11-24 (LR2) – renamed the return temp to `seeded_offset`, documented the sentinel 0x2600 write + GOT-base mirroring inline, and refreshed the metadata so the helper explains why the fake `__tls_get_addr` constants exist. |
| `103FA0_update_got_address` | `loader_rt` | 1 | 2025-11-24 (LR2) – renamed the PLT/disp locals (`tls_get_addr_stub`, `has_long_jump_prefix`, `stub_disp_offset`, `resolved_tls_entry`) and added inline comments covering each branch of the stub disassembly so the GOT math is easy to follow. |
| `104010_update_got_offset` | `loader_rt` | 1 | 2025-11-24 (LR2) – expanded the AutoDoc/inline note around the `_Llzma_block_buffer_decode_0` write so the GOT baseline refresh is captured in metadata. |
| `104080_find_link_map_l_name` | `loader_rt` | 1 | 2025-11-24 (LR2) – renamed the link-map trackers (`snapshot_cursor`, `best_runtime_map`, etc.), threaded inline comments through the import resolution, RELRO match, and dual-LEA verification, and synced everything via the pipeline. |
| `104370_find_dl_naudit` | `loader_rt` | 1 | 2025-11-24 (LR3) – documented the GLRO literal hunt plus the `_dl_audit_symbind_alt` cross-check, renamed the MOV scan/slot temps, and added inline anchors for the literal search and zeroed-slot adoption. |
| `1045E0_resolve_libc_imports` | `loader_rt` | 1 | 2025-11-24 (LR3) – expanded the plate around the fake allocator bootstrap, added inline notes for the `elf_parse` sanity check, resolver allocs, and success gate, and synced the locals metadata so the two import slots read clearly. |
| `104660_process_shared_libraries_map` | `loader_rt` | 1 | 2025-11-24 (LR3) – renamed the SONAME/classifier temps, captured the SONAME hashing + ld.so validation path, and annotated the liblzma hooks-blob carve out plus the libc import resolver hand-off. |
| `104A40_process_shared_libraries` | `loader_rt` | 1 | 2025-11-24 (LR3) – described the `_r_debug` lookup, scratch-state copy, and success propagation; inline comments now call out the `r_state` guard and the map-walker invocation that keeps the caller’s struct pristine. |
| `104AE0_find_link_map_l_audit_any_plt_bitmask` | `loader_rt` | 1 | 2025-11-24 (LR3) – documented the LEA/MOV/TEST state machine, renamed the register filters/import stubs, and dropped inline anchors for each scan state plus the single-bit mask validation. |
| `104EE0_find_link_map_l_audit_any_plt` | `loader_rt` | 1 | 2025-11-24 (LR4) – Named the register bitmaps/LEA cursors, documented the `_dl_audit_symbind_alt` sweep + register filter hand-off, and added inline anchors for the decoder wipe and bitmask dispatch. |
| `1051E0_find_dl_audit_offsets` | `loader_rt` | 1 | 2025-11-24 (LR4) – Clarified the ld.so audit walk, renamed the libcrypto basename buffer/allocator temps, and added inline comments for the `_dl_audit_symbind_alt` lookup, `find_link_map_l_name` handoff, and libname copy. |
| `105830_backdoor_setup` | `loader_rt` | 1 | 2025-11-24 (LR4) – Documented the GOT distance gate, shared-libraries walk, ld.so audit patch, sensitive-data/monitor/log discovery, secret_data telemetry, and audit-bit write-back; refreshed the sprawling locals metadata. |
| `106F30_backdoor_init_stage2` | `loader_rt` | 1 | 2025-11-24 (LR4) – Named the bootstrap scratch cursors, annotated the zeroization loops, retry/fallback flow, and GOT reset, and synced the inline breadcrumbs. |
| `10A794_backdoor_init` | `loader_rt` | 1 | 2025-11-24 (LR4) – Clarified the GOT bookkeeping/resolver swap, renamed the cpuid slot pointers, and added inline comments covering the relocation math plus the temporary stage-two patch. |
| `10A720_backdoor_entry` | `loader_rt` | 0 |  |
| `10A800_get_cpuid_modified` | `loader_rt` | 0 |  |
| `10A700_cpuid_gcc` | `loader_rt` | 0 |  |
| `1074B0_count_pointers` | `loader_rt` | 0 |  |
| `xzre_globals` | `loader_rt` | 1 | 2025-11-21 – Authored the missing AutoDoc so the liblzma data blob is documented as the shared hooks state (`ldso_ctx_t`, `global_ctx`, resolved imports, sshd/log metadata, payload queues). |
| `107030_c_strlen` | `loader_rt` | 0 |  |
| `107050_c_strnlen` | `loader_rt` | 0 |  |
| `107080_fd_read` | `loader_rt` | 0 |  |
| `1070F0_fd_write` | `loader_rt` | 0 |  |
| `107170_contains_null_pointers` | `loader_rt` | 0 |  |
| `103B80_dsa_key_hash` | `crypto_cmd` | 0 |  |
| `107190_chacha_decrypt` | `crypto_cmd` | 0 |  |
| `1072B0_sha256` | `crypto_cmd` | 0 |  |
| `107320_bignum_serialize` | `crypto_cmd` | 0 |  |
| `107510_rsa_key_hash` | `crypto_cmd` | 0 |  |
| `107630_verify_signature` | `crypto_cmd` | 0 |  |
| `107A20_sshd_get_sshbuf` | `crypto_cmd` | 0 |  |
| `107920_sshbuf_bignum_is_negative` | `crypto_cmd` | 0 |  |
| `107950_sshbuf_extract` | `crypto_cmd` | 0 |  |
| `1081D0_secret_data_get_decrypted` | `crypto_cmd` | 0 |  |
| `1094A0_run_backdoor_commands` | `crypto_cmd` | 0 |  |
| `10A240_hook_RSA_public_decrypt` | `crypto_cmd` | 0 |  |
| `10A2D0_hook_EVP_PKEY_set1_RSA` | `crypto_cmd` | 0 |  |
| `10A330_hook_RSA_get0_key` | `crypto_cmd` | 0 |  |
| `10A860_count_bits` | `crypto_cmd` | 0 |  |
| `10A880_get_string_id` | `crypto_cmd` | 0 |  |
| `10A990_secret_data_append_from_instruction` | `crypto_cmd` | 0 |  |
| `10AA00_secret_data_append_from_code` | `crypto_cmd` | 0 |  |
| `10AAC0_secret_data_append_singleton` | `crypto_cmd` | 0 |  |
| `10AB70_secret_data_append_item` | `crypto_cmd` | 0 |  |
| `10AB90_secret_data_append_from_address` | `crypto_cmd` | 0 |  |
| `10ABC0_secret_data_append_from_call_site` | `crypto_cmd` | 0 |  |
| `10ABE0_secret_data_append_items` | `crypto_cmd` | 0 |  |
