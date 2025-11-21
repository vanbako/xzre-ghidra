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
| `EL6` | Allocator/tls wrappers | `104060_get_lzma_allocator`, `10D000_lzma_check_init`, `10D008_tls_get_addr`, `10D010_lzma_free`, `10D018_lzma_alloc` |

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
| `101020_find_string_reference` | `opco_patt` | 0 |  |
| `101060_find_instruction_with_mem_operand_ex` | `opco_patt` | 0 |  |
| `101120_find_instruction_with_mem_operand` | `opco_patt` | 0 |  |
| `101170_find_add_instruction_with_mem_operand` | `opco_patt` | 0 |  |
| `102C60_find_addr_referenced_in_mov_instruction` | `opco_patt` | 0 |  |
| `102A50_elf_find_function_pointer` | `opco_patt` | 0 |  |
| `102D30_elf_find_string_references` | `opco_patt` | 0 |  |
| `1032C0_elf_find_string_reference` | `opco_patt` | 0 |  |
| `101210_fake_lzma_free` | `elf_mem` | 0 |  |
| `101240_elf_contains_vaddr_impl` | `elf_mem` | 0 |  |
| `1013A0_elf_contains_vaddr` | `elf_mem` | 0 |  |
| `1013B0_is_gnu_relro` | `elf_mem` | 0 |  |
| `1013D0_elf_parse` | `elf_mem` | 0 |  |
| `101880_elf_symbol_get` | `elf_mem` | 0 |  |
| `101B00_elf_symbol_get_addr` | `elf_mem` | 0 |  |
| `101B30_c_memmove` | `elf_mem` | 0 |  |
| `101B80_fake_lzma_alloc` | `elf_mem` | 0 |  |
| `101B90_elf_find_rela_reloc` | `elf_mem` | 0 |  |
| `101C30_elf_find_relr_reloc` | `elf_mem` | 0 |  |
| `101DC0_elf_get_reloc_symbol` | `elf_mem` | 0 |  |
| `101E60_elf_get_plt_symbol` | `elf_mem` | 0 |  |
| `101E90_elf_get_got_symbol` | `elf_mem` | 0 |  |
| `101EC0_elf_get_code_segment` | `elf_mem` | 0 |  |
| `101F70_elf_get_rodata_segment` | `elf_mem` | 0 |  |
| `1020A0_elf_find_string` | `elf_mem` | 0 |  |
| `102150_elf_get_data_segment` | `elf_mem` | 0 |  |
| `1022D0_elf_contains_vaddr_relro` | `elf_mem` | 0 |  |
| `102370_is_range_mapped` | `elf_mem` | 0 |  |
| `102440_j_tls_get_addr` | `elf_mem` | 0 |  |
| `102490_get_lzma_allocator_address` | `elf_mem` | 0 |  |
| `1024F0_get_elf_functions_address` | `elf_mem` | 0 |  |
| `103CE0_main_elf_parse` | `elf_mem` | 0 |  |
| `104030_init_elf_entry_ctx` | `elf_mem` | 0 |  |
| `104060_get_lzma_allocator` | `elf_mem` | 0 |  |
| `10D000_lzma_check_init` | `elf_mem` | 0 |  |
| `10D008_tls_get_addr` | `elf_mem` | 0 |  |
| `10D010_lzma_free` | `elf_mem` | 0 |  |
| `10D018_lzma_alloc` | `elf_mem` | 0 |  |
| `102550_sshd_find_main` | `sshd_recon` | 0 |  |
| `102FF0_sshd_find_monitor_field_addr_in_function` | `sshd_recon` | 0 |  |
| `103340_sshd_get_sensitive_data_address_via_krb5ccname` | `sshd_recon` | 0 |  |
| `103680_sshd_get_sensitive_data_address_via_xcalloc` | `sshd_recon` | 0 |  |
| `103870_sshd_get_sensitive_data_score_in_do_child` | `sshd_recon` | 0 |  |
| `103910_sshd_get_sensitive_data_score_in_main` | `sshd_recon` | 0 |  |
| `103990_sshd_get_sensitive_data_score_in_demote_sensitive_data` | `sshd_recon` | 0 |  |
| `103D50_sshd_get_sensitive_data_score` | `sshd_recon` | 0 |  |
| `103DB0_sshd_find_monitor_struct` | `sshd_recon` | 0 |  |
| `105410_sshd_find_sensitive_data` | `sshd_recon` | 0 |  |
| `1039C0_check_argument` | `sshd_recon` | 0 |  |
| `103A20_process_is_sshd` | `sshd_recon` | 0 |  |
| `107400_sshd_log` | `sshd_recon` | 0 |  |
| `107BC0_sshd_get_usable_socket` | `sshd_recon` | 0 |  |
| `107C60_sshd_get_client_socket` | `sshd_recon` | 0 |  |
| `107D50_sshd_patch_variables` | `sshd_recon` | 0 |  |
| `107DE0_sshd_configure_log_hook` | `sshd_recon` | 0 |  |
| `107EA0_check_backdoor_state` | `sshd_recon` | 0 |  |
| `107F20_extract_payload_message` | `sshd_recon` | 0 |  |
| `108270_sshd_proxy_elevate` | `sshd_recon` | 0 |  |
| `108080_mm_answer_keyverify_hook` | `sshd_recon` | 0 |  |
| `108100_mm_answer_authpassword_hook` | `sshd_recon` | 0 |  |
| `108EA0_mm_answer_keyallowed_hook` | `sshd_recon` | 0 |  |
| `10A3A0_mm_log_handler_hook` | `sshd_recon` | 0 |  |
| `108D50_decrypt_payload_message` | `sshd_recon` | 0 |  |
| `102770_init_ldso_ctx` | `loader_rt` | 0 |  |
| `1027D0_init_hooks_ctx` | `loader_rt` | 0 |  |
| `102850_init_shared_globals` | `loader_rt` | 0 |  |
| `102890_init_imported_funcs` | `loader_rt` | 0 |  |
| `102B10_validate_log_handler_pointers` | `loader_rt` | 0 |  |
| `103F60_update_cpuid_got_index` | `loader_rt` | 0 |  |
| `103F80_get_tls_get_addr_random_symbol_got_offset` | `loader_rt` | 0 |  |
| `103FA0_update_got_address` | `loader_rt` | 0 |  |
| `104010_update_got_offset` | `loader_rt` | 0 |  |
| `104080_find_link_map_l_name` | `loader_rt` | 0 |  |
| `104370_find_dl_naudit` | `loader_rt` | 0 |  |
| `1045E0_resolve_libc_imports` | `loader_rt` | 0 |  |
| `104660_process_shared_libraries_map` | `loader_rt` | 0 |  |
| `104A40_process_shared_libraries` | `loader_rt` | 0 |  |
| `104AE0_find_link_map_l_audit_any_plt_bitmask` | `loader_rt` | 0 |  |
| `104EE0_find_link_map_l_audit_any_plt` | `loader_rt` | 0 |  |
| `1051E0_find_dl_audit_offsets` | `loader_rt` | 0 |  |
| `105830_backdoor_setup` | `loader_rt` | 0 |  |
| `106F30_backdoor_init_stage2` | `loader_rt` | 0 |  |
| `10A794_backdoor_init` | `loader_rt` | 0 |  |
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
