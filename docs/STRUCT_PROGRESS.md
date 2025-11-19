# Struct Reverse-Engineering Progress

Track how many focused RE/documentation passes each struct has received. Increment the count and summarize changes whenever you touch a struct so future analysts can prioritize the lowest numbers first.

| Struct | Review Count | Notes |
| --- | --- | --- |
| `audit_ifaces` | 0 |  |
| `auditstate` | 0 |  |
| `backdoor_shared_globals_t` | 1 | Backdoor order #1 – renamed fields (authpassword hook, EVP hook, global_ctx_slot) and documented usage (2025-11-19). |
| `backdoor_shared_libraries_data_t` | 1 | Backdoor order #2 – renamed PLT slot/hooks_data pointers and documented their purpose (2025-11-19). |
| `backdoor_hooks_data_t` | 1 | Backdoor order #3 – annotated ldso/global/import/log/payload blocks + signed blob tail (2025-11-19). |
| `backdoor_hooks_ctx_t` | 1 | Backdoor order #4 – renamed ctx scratch/slot fields, documented symbind/RSA/mm hook pointers, noted the reserved log/monitor placeholders (2025-11-19). |
| `backdoor_payload_hdr_t` | 1 | Backdoor review order #5 – renamed stride/index/bias fields + doc’d ChaCha/cmd-type usage (2025-11-19). |
| `backdoor_payload_body_t` | 0 | Backdoor review order #6 – follows the header layout. |
| `backdoor_payload_t` | 0 | Backdoor review order #7 – wraps hdr/body into the final payload. |
| `backdoor_setup_params_t` | 0 | Backdoor review order #8 – parameters that feed payload deployment. |
| `backdoor_data_handle_t` | 0 | Backdoor review order #9 – helpers that move payload data around. |
| `backdoor_data_t` | 0 | Backdoor review order #10 – aggregate of decrypted/derived blobs. |
| `backdoor_tls_get_addr_reloc_consts_t` | 0 | Backdoor review order #11 – metadata for TLS GOT fixups. |
| `backdoor_cpuid_reloc_consts_t` | 0 | Backdoor review order #12 – final enum of CPUID GOT relocs. |
| `BIGNUM` | 0 |  |
| `BN_CTX` | 0 |  |
| `cmd_arguments_t` | 0 |  |
| `dasm_ctx_t` | 1 | Renamed decoder fields and documented each slot (2025-11-19) |
| `DSA` | 0 |  |
| `EC_GROUP` | 0 |  |
| `EC_KEY` | 0 |  |
| `EC_POINT` | 0 |  |
| `Elf64_Dyn` | 0 |  |
| `Elf64_Ehdr` | 0 |  |
| `Elf64_Phdr` | 0 |  |
| `Elf64_Rela` | 0 |  |
| `Elf64_Sym` | 0 |  |
| `elf_entry_ctx_t` | 0 |  |
| `elf_functions_t` | 0 |  |
| `elf_handles_t` | 0 |  |
| `elf_info_t` | 1 | Fields renamed/annotated (2025-11-18) |
| `ENGINE` | 0 |  |
| `EVP_CIPHER` | 0 |  |
| `EVP_CIPHER_CTX` | 0 |  |
| `EVP_MD` | 0 |  |
| `EVP_MD_CTX` | 0 |  |
| `EVP_PKEY` | 0 |  |
| `EVP_PKEY_CTX` | 0 |  |
| `fake_lzma_allocator_t` | 0 |  |
| `global_context_t` | 0 |  |
| `gnu_hash_table_t` | 0 |  |
| `got_ctx_t` | 0 |  |
| `imported_funcs_t` | 1 | Orig/PLT slots + helper stubs fully annotated (2025-11-18) |
| `instruction_search_ctx_t` | 0 |  |
| `kex` | 0 |  |
| `key_buf` | 0 |  |
| `key_ctx_t` | 0 |  |
| `key_payload_t` | 0 |  |
| `La_i86_regs` | 0 |  |
| `La_i86_retval` | 0 |  |
| `La_x32_regs` | 0 |  |
| `La_x32_retval` | 0 |  |
| `La_x86_64_regs` | 0 |  |
| `La_x86_64_retval` | 0 |  |
| `ldso_ctx_t` | 0 |  |
| `libc_imports_t` | 1 | Padding clarified and doc comments added (2025-11-18) |
| `lookup_t` | 0 |  |
| `lzma_allocator` | 0 |  |
| `lzma_check_state` | 0 |  |
| `lzma_sha256_state` | 0 |  |
| `main_elf_t` | 0 |  |
| `monitor` | 0 |  |
| `monitor_data_t` | 0 |  |
| `RSA` | 0 |  |
| `run_backdoor_commands_data_t` | 0 |  |
| `secret_data_item_t` | 0 |  |
| `sensitive_data` | 0 |  |
| `ssh` | 0 |  |
| `sshbuf` | 0 |  |
| `sshd_ctx_t` | 0 |  |
| `sshd_log_ctx_t` | 0 |  |
| `sshd_offsets_fields_t` | 0 |  |
| `sshd_offsets_t` | 0 |  |
| `sshd_payload_ctx_t` | 1 | Payload layout documented (2025-11-18) |
| `sshkey` | 0 |  |
| `string_item_t` | 0 |  |
| `string_references_t` | 0 |  |
| `tls_index` | 0 |  |
