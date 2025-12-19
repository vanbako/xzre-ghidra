# xzre Backdoor Functionality

## Overview
The implant hides inside liblzma’s CPUID IFUNC resolver and pivots into a loader that patches sshd at runtime. The loader discovers the host’s liblzma/libc/libcrypto/ld.so/sshd images, installs ld.so audit hooks to intercept sshd→libcrypto calls, and wires RSA-related PLT entries to attacker shims. Commands are smuggled through RSA key material, decrypted and signature-checked, then used to flip sshd logging, overwrite monitor state, and optionally run a payload via a privilege-escalating proxy.

## Bootstrapping via CPUID IFUNC
- `cpuid_ifunc_resolver_entry` is the exported cpuid resolver; the second invocation triggers `cpuid_ifunc_patch_got_for_stage2` while still fulfilling liblzma’s CPUID contract.
- `cpuid_ifunc_patch_got_for_stage2` locates the cpuid GOT slot, temporarily points it at `cpuid_ifunc_stage2_install_hooks`, and then restores the original target after priming the loader context.
- `cpuid_ifunc_stage2_install_hooks` builds scratch hook/global structures and keeps calling `hooks_ctx_init_or_wait_for_shared_globals` until the shared globals become available; a successful `backdoor_install_runtime_hooks` never returns, while failure zeroes the GOT context and emits a genuine CPUID to stay crash-safe.
The resolver path rides on glibc’s IFUNC mechanism so the backdoor runs before normal cpuid resolution. It rewrites the cpuid GOT entry in-place, hiding inside liblzma’s relocations. The staging context it builds is deliberately minimal—just enough to discover the surrounding ELF layout and swap back to the legitimate cpuid path if anything looks wrong—so early failures degrade cleanly without crashing sshd.

## Loader and Hook Installation
- `backdoor_install_runtime_hooks` drives the main staging path: it snapshots the caller’s GOT/stack, parses the main binary plus liblzma/libcrypto/libc/ld.so, and resolves PLT targets and relocation helpers. It copies the embedded `backdoor_hooks_data_t` blob out of liblzma, refreshes string-reference caches, seeds the global context (payload buffers, sshd/log contexts, import tables), and rewires ld.so’s audit table so `backdoor_symbind64` gates every sshd→libcrypto symbol bind. Updated hook pointers are copied back into liblzma so the cpuid GOT can safely resume.
- `scan_shared_libraries_via_r_debug` and `scan_link_map_and_init_shared_libs` walk `r_debug->r_map` to find the required ELF images, classify them, and gather relocation/segment data (including the liblzma RW slot that stores the hook blob and cpuid reloc constants).
- `libcrypto_imports_ready_or_install_bootstrap` and `init_backdoor_shared_globals` ensure the shared hook table and OpenSSL imports are populated before any hooks arm themselves, deferring to safe fallbacks when libc/libcrypto entries are unresolved.
- Embedded disassembler/pattern scanners: a minimal x86-64 decoder (`100020_x86_decode_instruction`) plus helpers (`find_riprel_mov`, `find_lea_with_displacement`, `find_rel32_call_instruction`, `find_riprel_ptr_lea_or_mov_load`, `find_function_bounds`/`find_endbr_prologue`, `elf_build_string_xref_table`, `elf_find_function_ptr_slot`) sweep sshd/libcrypto/liblzma code for specific MOV/LEA/CALL patterns, PLT stubs, and string xrefs. They return offsets to PLT/GOT slots, string constants, and monitor/log handler tables so `backdoor_install_runtime_hooks`, the ELF walkers, and the sshd-sensitive-data probes can patch stripped binaries without symbols.
The loader is conservative: it collects GOT pointers, PLT indices, and string IDs before patching anything, and it keeps a working copy of liblzma’s hook blob so updates can be rolled back. The audit-hook rewrite happens only after it proves libcrypto/libc imports exist and relocations line up. Its pattern scanners give it enough introspection to survive stripped sshd builds, letting it derive code/data offsets instead of relying on symbols. The result is a fully populated shared globals block (`backdoor_hooks_data_blob`) that all later hooks read from.

## Command Channel over RSA Hooks
- The RSA PLT entries for `RSA_public_decrypt`, `EVP_PKEY_set1_RSA`, and `RSA_get0_key` are repointed to shims that call `rsa_backdoor_command_dispatch` before delegating to the original OpenSSL symbols.
- `rsa_backdoor_command_dispatch` refuses to run unless the secret-data bitmap is complete and a valid RSA modulus/exponent pair is available. It treats the modulus bytes as a transport: decrypts the payload with ChaCha keys from `secret_data_decrypt_with_embedded_seed`, hashes cached sshd host keys, and verifies an embedded Ed448 signature. Commands toggle global state (sshd offsets, PAM/logging flags, socket selection, payload streaming state); execution requests build a `monitor_data_t` and invoke `sshd_monitor_cmd_dispatch`. Parse or signature failures flip `disable_backdoor` and let the real OpenSSL call proceed.
- `payload_stream_validate_or_poison` enforces a small state machine on buffered payload data so half-fetched messages reset the pipeline instead of corrupting sshd memory.
This path doubles as both gatekeeper and transport. The shims piggyback on legitimate RSA operations to smuggle encrypted commands, but they always verify that imports, payload buffers, and signature key material are live before acting. The ChaCha/Ed448 checks mean only an attacker with the private key can drive the dispatcher, and any parse error or missing prerequisite intentionally falls through to the host OpenSSL routine to keep sshd stable.

## Activation, Keys, and Attacker Actions
- Private key: every command blob is signed with an attacker-held Ed448 private key; the implant only carries the raw Ed448 public key (stored inside the 57-byte `secret_data` buffer and unwrapped via a two-pass ChaCha decrypt in `secret_data_decrypt_with_embedded_seed`). The first decrypt peels a seed that becomes the runtime ChaCha key, the second decrypt reveals the Ed448 key plus the symmetric payload material. Without the Ed448 private key, signatures fail and the hooks fall back to the original OpenSSL routines.
- How activation works: the attacker feeds a crafted RSA key through sshd/libcrypto so the RSA hooks see the modulus/exponent. The modulus encodes an encrypted header/body; the hooks decrypt it with the unwrapped ChaCha keys, splice in the host-key digest, and verify the Ed448 signature. In parallel, the monitor hook path (`mm_answer_keyallowed_payload_dispatch_hook`) can stream the same signed+encrypted payload through sshd’s monitor IPC, stepping a state machine gated by `payload_stream_validate_or_poison`; only a fully assembled, correctly signed payload advances to execution.
- Attacker capabilities once activated: patch the monitor dispatch table to force password/keyverify success responses; disable or filter sshd logging; toggle sshd variable hooks; select sockets for command I/O; queue auth payloads; or execute system/PAM commands via `sshd_monitor_cmd_dispatch` under attacker-chosen uid/gid. Any malformed payload or bad signature clears state, disables the backdoor flag, or exits sshd to avoid partial compromise.
- In-memory sshd reconfiguration for privilege escalation: `sshd_monitor_cmd_dispatch` (triggered by accepted commands) directly rewrites sshd globals to widen privileges. It forces `PermitRootLogin` to 3 (`permit_root_login_ptr`), can disable PAM by zeroing `use_pam`, and for certain command types swaps in forged monitor replies that mark authentication as successful. When the payload requests command execution it forks an elevated path: sets uid/gid via `setresuid/setresgid`, may call libc `system` with attacker-supplied commands, and rewires monitor request IDs/socket targets so sshd believes the forged exchange is legitimate. These changes live only in memory but persist for the lifetime of the sshd process.
Activation is deliberately multi-layered: the attacker must both possess the signing key and deliver well-formed payload chunks that pass the state machine and signature checks. Once active, commands can reconfigure sshd’s live structures—monitor tables, logging pointers, PAM flags, and root-login settings—without touching disk. The privilege-escalation path reuses sshd’s own monitor plumbing to push forged replies and then switches identities before running attacker commands, making the activity blend into sshd’s normal control channel.

## Command Types & Flags
The decrypted payload body exposes a `cmd_arguments_t` block so the attacker can toggle exit/log/PAM behaviour without crafting new opcodes. `rsa_backdoor_command_dispatch` stores the parsed block inside `key_ctx_t` and mirrors it into the `monitor_data_t` that eventually reaches `sshd_monitor_cmd_dispatch`.

- `cmd_type`: lower values drive in-place state updates (sshd variable patches, payload buffering, continuation fragments), while `cmd_type == 3` asks `sshd_monitor_cmd_dispatch` to forge a `MONITOR_REQ_KEYALLOWED` exchange (building temporary RSA/BIGNUM objects with the attacker modulus/exponent).
- `control_flags`: bit0 exits sshd after dispatch, bits1–4 drive the logging hook/setlogmask/filter prerequisites, bit5 forces manual socket selection, bit6 zeros `use_pam`, and bit7 keeps the hook in “wait for replies” mode so opcode 0 can treat the payload tail as `sshd_offsets` overrides.
- `monitor_flags`: bit0 announces that continuation chunks prepend an 8-byte length tag, bits1/2 repurpose `payload_hint` so opcode 0 can rewrite `sshd_offsets`, bits3–5 encode the socket ordinal, and the high bits choose how opcode 3 sources payload bytes (0x40 = exit immediately, 0x80 = scrape the ChaCha blob from the stack, 0xC0 = payload pointers already valid).
- `request_flags`: the low five bits either override the MONITOR_REQ id or encode an additional socket number, bit5 requests that `sshd_monitor_cmd_dispatch` pull an sshbuf via `sshd_find_forged_modulus_sshbuf`, and bit6 turns the trailing payload bytes into packed offset fields.
- `payload_hint`: a 16-bit union reused as a payload length for continuation chunks or as extra `sshd_offsets` bits when opcode 0 is patching monitor metadata.

The runtime keeps two helper structs in sync while processing these flags. `rsa_backdoor_command_dispatch_data_t` owns the staging buffers (socket receive queues, host-key digests, monitor union, Ed448 key cache), while `key_ctx_t` carries the decrypted payload, modulus/exponent pointers, ChaCha nonce/IV snapshots, and the unwrapped Ed448 key so subsequent chunks can be verified without re-reading `secret_data`.

## SSHD Monitor and Logging Hooks
- Monitor hooks (`mm_answer_keyverify_send_staged_reply_hook`, `mm_answer_authpassword_send_reply_hook`, `mm_answer_keyallowed_payload_dispatch_hook`) short-circuit sshd’s monitor protocol: they replay prebuilt success buffers or synthesize valid replies, skip the real authentication logic, and mirror sshd dispatch bookkeeping. Any structural error falls back to libc `exit()` to avoid running partially patched.
- `sshd_install_mm_log_handler_hook` validates caller-supplied handler/context pointers and swaps in `mm_log_handler_hide_auth_success_hook` when flags permit, allowing the implant to silence or filter sshd syslog output while preserving the original handler for restoration.
- `sshd_score_sensitive_data_candidate` plus its helpers locate sensitive sshd state (monitor structures, payload buffers, log contexts) so later commands know where to write.
These hooks are the visible tip of the backdoor inside sshd: they edit the monitor dispatch table to route logins through attacker code, serve canned replies so sshd believes authentication passed, and optionally silence syslog by swapping handlers. They maintain the original function/context pointers so they can restore or chain correctly, lowering crash risk. Sensitive-data probes keep track of where sshd’s buffers and metadata live so future writes land in the right place across versions.

## Component Breakdown
- **Resolver & loader:** CPUID IFUNC entry (`cpuid_ifunc_resolver_entry`/`cpuid_ifunc_patch_got_for_stage2`) hands control to the stage-two loader, which uses GOT math and cpuid reloc constants to stay position-independent.
- **Shared hook blob:** `backdoor_hooks_data_blob` in liblzma holds the shared `global_context_t`, resolved libc/libcrypto imports, sshd/log metadata, and signed payload bytes; `init_backdoor_shared_globals` publishes these pointers to all hooks.
- **Library discovery:** `scan_link_map_and_init_shared_libs`/`scan_shared_libraries_via_r_debug` build an `elf_handles_t` map for sshd, libcrypto, liblzma, libc, and ld.so, collecting PLT indices and rw/ro/code segments needed for later patching.
- **Audit/GOT interception:** ld.so audit pointers are rewritten so `backdoor_symbind64` runs on sshd→libcrypto binds; the allocator/tls shims (`fake_lzma_alloc_resolve_symbol`, `tls_get_addr_trampoline`) keep the loader stable while relocations are in flux.
- **Command dispatcher:** RSA shims funnel into `rsa_backdoor_command_dispatch`, which decrypts, verifies, and applies attacker commands or defers to the real OpenSSL routine if validation fails.
- **Monitor/log hooks:** The mm_* handlers and log hook let the payload bypass authentication, inject replies, and mute noisy syslog lines while retaining the ability to restore sshd’s originals.

## Secret-Data Recorder & Obfuscated Strings
- Every ELF walker, relocation scanner, and sshd heuristic starts by calling one of the `secret_data_append_*` helpers. `secret_data_append_bits_from_call_site`, `_from_address`, `_from_code`, and `_from_instruction` feed a 0x1C8-bit cursor (`secret_data_shift_cursor_t`) inside `global_context_t->secret_data`, while `secret_data_append_items_batch` ensures each `secret_data_item_t` descriptor only runs once (gated by the `shift_operation_flags` array). If any appender fails, the caller aborts instead of mutating GOT slots or monitor state off-record.
- `rsa_backdoor_command_dispatch` refuses to decrypt payloads unless `ctx->secret_bits_filled == 0x1C8`, `ctx->sshd_log_via_sshlogv_ctx` is non-null, and the loader recorded every expected attestation. That ties command execution to the success of the discovery/telemetry path and prevents partially initialised hosts from running attacker opcodes.
- The `encrypted_secret_data[57]` buffer inside `global_context_t` doubles as storage for the bit-shift log and for the encrypted Ed448/ChaCha material. `secret_data_decrypt_with_embedded_seed` performs a two-step ChaCha decrypt: a built-in key unwraps a 0x30-byte seed, the seed becomes the runtime ChaCha key, and a second decrypt reveals the Ed448 public key plus the ChaCha key/IV that decrypt payload bodies.
- String lookups never embed plaintext. `encoded_string_id_lookup` walks the packed trie baked into `string_action_data`/`string_mask_data` using `popcount_u64` to choose each branch; every call reports itself via `secret_data_append_bits_from_addr_or_ret` so the attestation log mirrors successful string scrapes. The resulting encoded IDs let the loader find sshd banner strings, log format specifiers, and monitor helpers without shipping readable literals.
- Because each major helper emits these breadcrumbs, the secret-data bitmap doubles as an integrity log and a kill switch—if any instrumentation diverges (missing string, failed relocation scan, etc.), `secret_bits_filled` never reaches 0x1C8 and the RSA hooks fall back to the genuine OpenSSL routines permanently.

## Loader & RSA Hook Dependencies (Mermaid)
```mermaid
flowchart TD
    cpuid_entry["cpuid_ifunc_resolver_entry (IFUNC resolver)"]
    init1["cpuid_ifunc_patch_got_for_stage2 (GOT patch)"]
    init2["cpuid_ifunc_stage2_install_hooks (scratch globals/hooks)"]
    setup["backdoor_install_runtime_hooks (loader)"]
    libwalk["scan_link_map_and_init_shared_libs / scan_shared_libraries_via_r_debug"]
    globals["init_backdoor_shared_globals → backdoor_hooks_data_blob"]
    imports["libcrypto_imports_ready_or_install_bootstrap (OpenSSL PLT readiness)"]
    audit["ld.so audit hooks → backdoor_symbind64"]
    rsa_hooks["PLT shims: RSA_public_decrypt / EVP_PKEY_set1_RSA / RSA_get0_key"]
    dispatcher["rsa_backdoor_command_dispatch"]
    state["payload_stream_validate_or_poison / secret_data_decrypt_with_embedded_seed"]
    sshd_hooks["mm_* monitor hooks / sshd_install_mm_log_handler_hook"]
    payload["sshd_monitor_cmd_dispatch / payload/log mutations"]

    cpuid_entry --> init1 --> init2 --> setup
    setup --> libwalk --> globals
    setup --> imports
    setup --> audit --> rsa_hooks --> dispatcher
    dispatcher --> state
    dispatcher --> sshd_hooks
    dispatcher --> payload
```

## SSHD Monitor & Log Hooks (Mermaid)
```mermaid
flowchart TD
    globals["global_ctx / backdoor_hooks_data_blob"]
    payload_ctx["sshd_payload_ctx (decrypted payload buffers)"]
    monitor_table["sshd monitor dispatch table"]
    mm_keyverify["mm_answer_keyverify_send_staged_reply_hook"]
    mm_authpw["mm_answer_authpassword_send_reply_hook"]
    mm_keyallowed["mm_answer_keyallowed_payload_dispatch_hook"]
    log_cfg["sshd_install_mm_log_handler_hook"]
    log_hook["mm_log_handler_hide_auth_success_hook (syslog filter)"]
    fd_write_full["fd_write_full (reply emission)"]
    exit_fn["libc exit (safety)"]

    globals --> payload_ctx
    globals --> monitor_table
    log_cfg --> log_hook
    payload_ctx --> mm_keyverify
    payload_ctx --> mm_authpw
    payload_ctx --> mm_keyallowed
    mm_keyverify --> fd_write_full
    mm_authpw --> fd_write_full
    mm_keyallowed --> fd_write_full
    log_hook --> fd_write_full
    mm_keyverify --> monitor_table
    mm_authpw --> monitor_table
    mm_keyallowed --> monitor_table
    mm_keyverify --> exit_fn
    mm_authpw --> exit_fn
    mm_keyallowed --> exit_fn
```

## RSA Command Dispatcher (Mermaid)
```mermaid
flowchart TD
    rsa_hooks["RSA PLT shims"]
    run_cmds["rsa_backdoor_command_dispatch"]
    secret["secret_data_decrypt_with_embedded_seed"]
    sig["verify_ed448_signed_payload (Ed448 over host-key digest)"]
    chacha["chacha20_decrypt"]
    state["payload_stream_validate_or_poison"]
    elevate["sshd_monitor_cmd_dispatch"]
    patch_vars["sshd_patch_permitrootlogin_usepam_and_hook_authpassword / monitor table rewrites"]

    rsa_hooks --> run_cmds
    run_cmds --> secret --> chacha --> sig
    run_cmds --> state
    run_cmds --> elevate
    run_cmds --> patch_vars
```

## Payload Assembly & State Machine (Mermaid)
```mermaid
flowchart TD
    keyallowed["mm_answer_keyallowed_payload_dispatch_hook"]
    extract["sshbuf_extract_rsa_modulus"]
    decrypt_payload["payload_stream_decrypt_and_append_chunk"]
    state["payload_stream_validate_or_poison"]
    stash["payload_data buffer"]
    run_cmds["rsa_backdoor_command_dispatch"]

    keyallowed --> state
    keyallowed --> extract --> decrypt_payload --> stash
    state --> stash
    stash --> run_cmds
```

## Privilege Escalation & Monitor Forgeries (Mermaid)
```mermaid
flowchart TD
    run_cmds["rsa_backdoor_command_dispatch"]
    elevate["sshd_monitor_cmd_dispatch"]
    authhooks["mm_answer_keyverify_send_staged_reply_hook / mm_answer_authpassword_send_reply_hook"]
    loghook["sshd_install_mm_log_handler_hook / mm_log_handler_hide_auth_success_hook"]
    pam["use_pam_ptr zeroed"]
    permitroot["permit_root_login_ptr = 3"]
    setids["setresuid/setresgid"]
    system["libc system() / monitor reply forgery"]

    run_cmds --> elevate
    elevate --> permitroot
    elevate --> pam
    elevate --> setids
    elevate --> system
    run_cmds --> authhooks
    run_cmds --> loghook
```

## Struct Layouts (Mermaid)
Understanding the backdoor’s internal structs makes it easier to trace how state flows between the loader, hooks, and payload handlers. The diagrams below capture the layouts and relationships that matter most in this document.

### `backdoor_hooks_data_t` Container
Lives in liblzma’s `.data` segment and glues all loader state together.

```mermaid
flowchart LR
    hooks["backdoor_hooks_data_t (.data blob)"]
    ldso["ldso_ctx_t\nld.so audit / GOT snapshot"]
    global_ctx["global_context_t\nruntime shared by hooks"]
    imports["imported_funcs_t\nresolved libcrypto helpers"]
    sshdctx["sshd_ctx_t\nmonitor hook metadata"]
    libc["libc_imports_t\nread/write/pselect/exit"]
    logctx["sshd_log_via_sshlogv_ctx_t\nmm_log_handler state"]
    payload["signed_data_size + signed_data[]\nattacker-signed payload tail"]

    hooks --> ldso
    hooks --> global_ctx
    hooks --> imports
    hooks --> sshdctx
    hooks --> libc
    hooks --> logctx
    hooks --> payload
```

### `global_context_t` Runtime State
Authoritative runtime store every hook consults: imports, sshd/monitor metadata, payload buffers, and secret-data progress.

```mermaid
flowchart LR
    global["global_context_t"]
    imports["Imports\n- imported_funcs_t *\n- libc_imports_t *"]
    sshdmeta["SSHD metadata\n- sshd_ctx_t *\n- sensitive_data *\n- sshd_log_via_sshlogv_ctx_t *\n- monitor **slot\n- sshd_offsets_t"]
    knobs["Guards/flags\n- uses_endbr64\n- disable_backdoor\n- exit_flag\n- caller_uid"]
    strings["String anchors\n- ssh_rsa_cert_alg\n- rsa_sha2_256_alg"]
    bounds["Bounds\n- sshd text/data start/end\n- liblzma text start/end\n- sshd_main_entry"]
    payload["Payload streaming\n- payload_buffer*\n- payload_buffer_size\n- payload_bytes_buffered\n- payload_ctx*\n- payload_state\n- sshd_host_pubkey_idx"]
    sockbuf["Socket staging\n- sock_read_len\n- sock_read_buf[64]"]
    secret["Secret-data tracking\n- encrypted_secret_data[57]\n- shift_operation_flags[31]\n- secret_bits_filled"]

    global --> imports
    global --> sshdmeta
    global --> knobs
    global --> strings
    global --> bounds
    global --> payload
    global --> sockbuf
    global --> secret
    payload --> sockbuf
```

### `sshd_payload_ctx_t` Payload Blob
Represents the ChaCha-decrypted command blob produced by `mm_answer_keyallowed_payload_dispatch_hook`.

```mermaid
classDiagram
    class sshd_payload_ctx_t {
        +payload_total_size : u16
        +signed_header_prefix[0x39]
        +command_type : u8
        +ed448_signature[0x72]
        +body_payload_offset : u16
        +payload_body[]
    }
```

### `monitor_data_t` Elevation Bundle
Argument block handed to `sshd_monitor_cmd_dispatch` after `rsa_backdoor_command_dispatch` parses the opcode and arguments.

```mermaid
classDiagram
    class monitor_data_t {
        +cmd_type : u32
        +args : cmd_arguments_t *
        +rsa_n : const BIGNUM *
        +rsa_e : const BIGNUM *
        +payload_body : u8 *
        +payload_body_size : u16
        +rsa : RSA *
    }
```

### `elf_handles_t` Parsed Images
Helper struct produced by the loader so every pass can touch the same parsed ELF descriptors without re-reading `r_debug`.

```mermaid
flowchart TD
    handles["elf_handles_t"]
    sshd["elf_info_t\nsshd"]
    ldso["elf_info_t\nld-linux.so"]
    libc["elf_info_t\nlibc"]
    liblzma["elf_info_t\nliblzma"]
    libcrypto["elf_info_t\nlibcrypto"]

    handles --> sshd
    handles --> ldso
    handles --> libc
    handles --> liblzma
    handles --> libcrypto
```

## Dynamic RE Prereqs & Tips
- Keys and payloads: you need a valid Ed448 signing key and a payload encrypted with the baked-in ChaCha key/IV pairs (`secret_data_decrypt_with_embedded_seed` unwraps the public key and keying material). Without a valid signature on the modulus-encoded payload, `rsa_backdoor_command_dispatch` will fall back to the host OpenSSL routines.
- Imports and globals: the loader and hooks expect resolved libcrypto/libc imports and a non-null `backdoor_hooks_data_blob` with payload buffers. If you instrument dynamically, ensure the headless refresh has applied metadata so imports resolve, or patch the import table in-memory to point at real OpenSSL/libc functions before invoking the hooks.
- Payload assembly: the monitor path (`mm_answer_keyallowed_payload_dispatch_hook`) steps a state machine (`payload_stream_validate_or_poison`) and requires sane lengths before decrypting or acting. When replaying traffic, feed well-formed chunks in order and keep `payload_state`/sizes consistent, or temporarily patch out the state checks to observe deeper behavior.
- Safety exits: monitor hooks and the dispatcher call libc `exit()` or disable the backdoor on malformed inputs (e.g., null pointers, unexpected sizes). For exploratory tracing, you can NOP those exits or force `do_orig` non-null to keep the process alive while you observe.
- Elevation paths: `sshd_monitor_cmd_dispatch` rewrites in-memory sshd globals (PermitRootLogin, PAM flag, monitor IDs) and may call `system`. When testing, run under a nonproduction sshd and confirm `setresuid/setresgid`/PAM calls are safe, or stub those imports to avoid actual privilege changes.
