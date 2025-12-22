# Struct Reverse-Engineering Progress

Track how many focused RE/documentation passes each struct has received. Increment the count and summarize changes whenever you touch a struct so future analysts can prioritize the lowest numbers first.

## Recommended Struct Review Order

1. **Loader / Relocation Core** – Nail down the structs that drive GOT patching and loader context first so later analyses rest on solid ground: `elf_entry_ctx_t`, `got_ctx_t`, `backdoor_cpuid_reloc_consts_t`, `backdoor_tls_get_addr_reloc_consts_t`, `backdoor_data_t`, `backdoor_data_handle_t`, `backdoor_shared_libraries_data_t`, `elf_handles_t`, `elf_info_t`, `global_context_t`.
2. **Hook Orchestration & Metadata** – Next document the structs that thread state between loader passes and liblzma-resident blobs: `backdoor_shared_globals_t`, `backdoor_hooks_ctx_t`, `backdoor_hooks_data_t`, `imported_funcs_t`, `string_references_t`, `string_item_t`, `backdoor_install_runtime_hooks_params_t`.
3. **SSHD / Monitor State** – Once the loader is clear, focus on sshd-facing structs so sensitive-data scans and hook trampolines can be reasoned about: `sshd_ctx_t`, `sshd_log_via_sshlogv_ctx_t`, `monitor`, `monitor_data_t`, `sshd_payload_ctx_t`, `rsa_backdoor_command_dispatch_data_t`, `secret_data_item_t`, `secret_data_shift_cursor_t`.
4. **Payload / Crypto Plumbing** – With runtime structures mapped, cover the payload buffers and key material used when executing attacker commands: `backdoor_payload_hdr_t`, `backdoor_payload_body_t`, `backdoor_payload_t`, `key_payload_t`, `key_ctx_t`, `cmd_arguments_t`, `key_buf`.
5. **Third-Party Types** – Finally, align OpenSSH/OpenSSL/XZ imports with the reversed code so cross-references stay accurate: `sshbuf`, `sshkey`, `RSA`, `EVP_*`, `EC_*`, `kex`, `auditstate`, `audit_ifaces`, etc. These can be treated opportunistically once the bespoke structs are documented.

| Struct | Review Count | Notes |
| --- | --- | --- |
| `audit_ifaces` | 0 |  |
| `auditstate` | 0 |  |
| `backdoor_shared_globals_t` | 1 | Backdoor order #1 – renamed fields (authpassword hook, EVP hook, global_ctx_slot) and documented usage (2025-11-19). |
| `backdoor_shared_libraries_data_t` | 1 | Backdoor order #2 – renamed PLT slot/hooks_data pointers and documented their purpose (2025-11-19). |
| `backdoor_hooks_data_t` | 1 | Backdoor order #3 – annotated ldso/global/import/log/payload blocks + signed blob tail (2025-11-19). |
| `backdoor_hooks_ctx_t` | 1 | Backdoor order #4 – renamed ctx scratch/slot fields, documented symbind/RSA/mm hook pointers, noted the reserved log/monitor placeholders (2025-11-19). |
| `backdoor_payload_hdr_t` | 2 | Backdoor review order #5 – flattened header layout so decomp prefers `cmd_type_*` fields (2025-12-15). |
| `backdoor_payload_body_t` | 1 | Backdoor review order #6 – renamed the signature/args/data slots to `ed448_signature`/`cmd_flags`/`monitor_payload`, documented the Ed448 coverage and 0x87 payload offset (2025-11-19). |
| `backdoor_payload_t` | 1 | Backdoor review order #7 – renamed the raw bytes view, documented the parsed header/body union, and noted why the hooks need both representations (2025-11-19). |
| `backdoor_install_runtime_hooks_params_t` | 1 | Backdoor review order #8 – renamed the scratch/pointer fields, documented the dummy lzma state plus entry ctx usage (2025-11-19). |
| `backdoor_data_handle_t` | 1 | Backdoor review order #9 – renamed the pointers to `runtime_data`/`cached_elf_handles` and documented why helpers need both views (2025-11-19). |
| `backdoor_data_t` | 1 | Backdoor review order #10 – renamed the link_map snapshots + allocator fields and documented the sshd string table + ELF handles (2025-11-19). |
| `backdoor_tls_get_addr_reloc_consts_t` | 1 | Backdoor review order #11 – renamed the displacement slots (`plt_stub_offset_from_got_anchor` / `random_slot_offset_from_got_anchor`) and documented the anchors each delta targets (2025-11-19). |
| `backdoor_cpuid_reloc_consts_t` | 1 | Backdoor review order #12 – renamed the GOT displacement/index fields so they describe the cpuid random slot and stage-two trampoline anchors (2025-11-19). |
| `BIGNUM` | 0 |  |
| `BN_CTX` | 0 |  |
| `cmd_arguments_t` | 1 | Payload/Crypto review – renamed the three flag bytes to control/monitor/request flags, annotated their bit semantics (log hook, PAM, socket/payload sourcing), and documented how payload_hint doubles as a length vs. sshd_offsets overlay (2025-11-21). |
| `dasm_ctx_t` | 7 | Renamed decoder fields and documented each slot (2025-11-19); added `x86_prefix_state_t` overlays (`flags_u32`, `modrm_bytes`) so scanners stop relying on raw prefix `_N_M_` slices (2025-12-16); added `opcode_window_dword` overlay to replace `_40_4_` opcode slices (2025-12-21); swapped the anonymous opcode-window union for a named `dasm_opcode_window_t` field and documented the opcode-window map prefixes (2025-12-21); typed `prefix.decoded.flags` as `InstructionFlags_t` and rewrote DF1_* usage in decoder/scanner exports (2025-12-22); typed `prefix.decoded.flags2` as `InstructionFlags2_t` and rewrote DF2_* usage in decoder/scanner exports (2025-12-22); typed `prefix.modrm_bytes.rex_byte` as `RexPrefixFlags_t` and rewrote REX_* usage in decoder/scanner exports (2025-12-22). |
| `dasm_opcode_window_t` | 1 | Added the `window_bytes` overlay (`low_byte` + `high_bytes[3]`) so the decoder no longer emits `_1_3_` byte slices (2025-12-21). |
| `DSA` | 0 |  |
| `EC_GROUP` | 0 |  |
| `EC_KEY` | 0 |  |
| `EC_POINT` | 0 |  |
| `Elf64_Dyn` | 0 |  |
| `Elf64_Ehdr` | 0 |  |
| `Elf64_Phdr` | 1 | Retyped `p_flags` as `ElfProgramHeaderFlags_t` (PF_R/PF_W/PF_X bitmask) to make segment permissions explicit (2025-12-22). |
| `Elf64_Rela` | 0 |  |
| `Elf64_Sym` | 0 |  |
| `elf_entry_ctx_t` | 1 | Documented the cpuid relocation anchors (`cpuid_random_symbol_addr`, resolver frame/GOT slot reuse) and clarified the GOT bookkeeping role (2025-11-19). |
| `elf_functions_t` | 1 | Documented the 7-slot table layout and labeled the repurposed helper pointers (2025-12-20). |
| `elf_handles_t` | 1 | Renamed handles to sshd/ld.so/libc/liblzma/libcrypto and annotated their roles (2025-11-20). |
| `elf_info_t` | 2 | Fields renamed/annotated (2025-11-18); typed `feature_flags` as `ElfFlags_t` (2025-12-22). |
| `ENGINE` | 0 |  |
| `EVP_CIPHER` | 0 |  |
| `EVP_CIPHER_CTX` | 0 |  |
| `EVP_MD` | 0 |  |
| `EVP_MD_CTX` | 0 |  |
| `EVP_PKEY` | 0 |  |
| `EVP_PKEY_CTX` | 0 |  |
| `fake_lzma_allocator_t` | 0 |  |
| `global_context_t` | 1 | Renamed context fields (imports, monitor slot, code/data bounds, payload/secret tracking) and annotated roles (2025-11-20). |
| `gnu_hash_table_t` | 1 | Modeled GNU hash header/bloom layout and rewired `elf_info_parse` exports to use named fields + bucket/chain math (2025-12-20). |
| `got_ctx_t` | 1 | Loader review #13 – renamed the GOT anchor/slot/index fields (`tls_got_entry`, `cpuid_got_slot`, `cpuid_slot_index`, `got_base_offset`) and documented how cpuid_random_symbol_addr is used to rebuild the GOT base (2025-11-20). |
| `imported_funcs_t` | 1 | Orig/PLT slots + helper stubs fully annotated (2025-11-18) |
| `instruction_register_bitmap_t` | 2 | Added the 4-byte `{allowed_regs, reg_index}` union used by the audit instruction matcher so exports stop relying on `_0_3_` slices (2025-12-16); added a `high_word` overlay for the reg_index/reserved halfword so scanners stop using `_2_2_` slices (2025-12-21). |
| `instruction_search_offset_t` | 1 | Added an 8-byte `{offset, reserved}` union for the match displacement so exports stop relying on `_0_4_` slices while preserving the ctx layout (2025-12-16). |
| `instruction_search_ctx_t` | 1 | Audit scanner ctx pass – retagged `offset_to_match` + register bitmap pointers to the new helper types so `find_l_audit_any_plt_mask_via_symbind_alt*` exports named fields (2025-12-16). |
| `kex` | 0 |  |
| `key_buf` | 1 | Broke the opaque `words[]` blob into `seed_key`/`seed_iv`/`encrypted_seed`/`payload_iv`, documenting how the first ChaCha pass unwraps the runtime key and the second reuses it with a fixed IV (2025-11-21). |
| `key_ctx_t` | 1 | Payload/Crypto pass – renamed the modulus/exponent/args/payload scratch to describe the ChaCha + Ed448 reuse, annotated the hostkey digest slot and nonce/IV snapshots, and documented the secret_data linkage (2025-11-21). |
| `key_payload_t` | 2 | Backdoor review order #7.2 – retagged the ChaCha frame as `{header, encrypted_body_length, encrypted_body[]}` and refreshed locals/inline anchors so payload_stream_decrypt_and_append_chunk exports clean field accesses (2025-12-15). |
| `key_payload_cmd_frame_t` | 1 | Added a documented scratch overlay (cmd flag bytes + modulus ciphertext) to keep RSA-path payload parsing readable (2025-12-15). |
| `La_i86_regs` | 0 |  |
| `La_i86_retval` | 0 |  |
| `La_x32_regs` | 0 |  |
| `La_x32_retval` | 0 |  |
| `La_x86_64_regs` | 0 |  |
| `La_x86_64_retval` | 0 |  |
| `ldso_ctx_t` | 1 | Named `libcrypto_basename_buf` and documented how stage one uses it to forge `link_map::l_name` during the ld.so audit install (2025-12-18). |
| `libc_imports_t` | 1 | Padding clarified and doc comments added (2025-11-18) |
| `lookup_t` | 1 | Modeled the glibc link_map prefix (l_addr/l_name/l_ld/l_next/l_prev) so link_map scans export named fields (2025-12-20). |
| `lzma_allocator` | 0 |  |
| `lzma_check_state` | 0 |  |
| `lzma_sha256_digest_state` | 0 |  |
| `main_elf_t` | 1 | Annotated ld.so header pointer + __libc_stack_end output slot and refreshed exports (2025-12-20). |
| `monitor` | 1 | Privsep struct review #1 – renamed the RPC/log fd fields to describe child↔monitor direction, clarified the pkex table pointer, and documented the monitor PID slot (2025-11-21). |
| `monitor_data_t` | 1 | Privsep struct review #2 – documented cmd opcode usage, annotated the RSA/payload pointers, and renamed the padding slots to explain why the runtime_data union keeps them aligned (2025-11-21). |
| `RSA` | 0 |  |
| `rsa_backdoor_command_dispatch_data_t` | 1 | RSA dispatcher struct pass – renamed the payload sizing/do_orig/hostkey fields, documented the staging union (socket RX vs. Ed448 key data), and refreshed the metadata/export (2025-11-23). |
| `secret_data_item_t` | 1 | Renamed entries to anchor_pc/bit_cursor/operation_slot/bits_to_shift/ordinal and annotated how each controls the secret-data attestation flow (2025-11-21). |
| `secret_data_shift_cursor_t` | 1 | Renamed the union view to bit_position/signed_bit_position/intra_byte_bit/byte_offset and documented how it indexes global_ctx->secret_data (2025-11-21). |
| `sensitive_data` | 1 | Documented the host key table fields and retagged sensitive-data helpers to use `sensitive_data *` parameters (2025-12-20). |
| `ssh` | 0 |  |
| `sshbuf` | 1 | Aligned to the OpenSSH 9.7p1 layout and annotated the d/cd/off/size/max_size/alloc/readonly/refcount/parent fields (2025-12-20). |
| `sshd_hostkey_index_t` | 0 | Newly documented wrapper around the host_pubkeys[] ordinal so payload verification code stops referencing `_union_110`. |
| `sshd_ctx_t` | 1 | Renamed the monitor hook entries/slots, keyed the staged keyverify/authpassword payload buffers, and documented the authfmt rodata probe + PAM/root globals (2025-11-20). |
| `sshd_log_via_sshlogv_ctx_t` | 1 | Renamed the logging gate/syslog flags, clarified the handler/ctx slot pointers, and documented the sshlogv/log-fragment anchors used by the hook (2025-11-20). |
| `sshd_offsets_fields_t` | 1 | Packed offsets review – clarified the signed-byte ordering/meaning of the monitor+kex+sshbuf indices and refreshed the exports (2025-12-15). |
| `sshd_offsets_t` | 1 | Packed offsets review – replaced the anonymous union with named {fields, bytes, raw_value} views so `sshd_find_forged_modulus_sshbuf`/`sshbuf_extract_ptr_and_len` use real member names instead of `field0_0x0` arithmetic (2025-12-15). |
| `sshd_payload_ctx_t` | 1 | Payload layout documented (2025-11-18) |
| `sshkey` | 2 | Trimmed to the minimal OpenSSH prefix (type/flags/rsa/dsa/ecdsa/ed25519_pk) and dropped XMSS/FIDO/shielded tail fields (2025-12-20); retyped `sshkey.type` to `sshkey_type_t` for KEY_* enums (2025-12-22). |
| `string_item_t` | 1 | Renamed the padding field and clarified how each entry captures the function bounds/xref for a decoded string (2025-11-20). |
| `string_references_t` | 1 | Broke out the 27 entries into named sshd/PAM/log anchors and annotated what each string reference is used to find (2025-11-20). |
| `tls_index` | 0 |  |
