# Backdoor Execution Flow (Simple)

## Trigger: ld.so runs the IFUNC resolver
When sshd loads liblzma, the dynamic loader (ld.so) resolves an IFUNC symbol and
invokes the resolver inside the library. In this implant, that resolver is
`cpuid_ifunc_resolver_entry`. It returns a CPUID implementation so liblzma looks
normal, but it also bootstraps the backdoor.

## What the resolver does
The resolver has a two-step bootstrap:
- On a later invocation it calls `cpuid_ifunc_patch_got_for_stage2`, which
  temporarily points the CPUID GOT slot at `cpuid_ifunc_stage2_install_hooks`.
- `cpuid_ifunc_stage2_install_hooks` builds a minimal context and calls
  `backdoor_install_runtime_hooks`. If anything fails, it restores the original
  CPUID target and returns a genuine CPUID result so sshd keeps running.

## What the loader does after bootstrap
`backdoor_install_runtime_hooks` does the heavy lifting:
- Finds other loaded ELF images (sshd, libcrypto, libc, ld.so) by walking
  ld.so's link_map and parsing segments/relocations.
- Uses opcode and string scanners to locate key sshd data structures and
  function entry points when symbols are stripped or version-dependent.
- Installs ld.so audit hooks (via `backdoor_symbind64`) to intercept
  sshd->libcrypto symbol binds.
- Rewrites RSA PLT entries so OpenSSL calls are redirected to backdoor shims.

## Extra mechanics the loader sets up
These are still “plumbing” details, but they matter for how the hooks behave:
- Audit metadata: it derives ld.so audit offsets and link_map `l_name` fields so
  the audit hook can spoof libcrypto’s name and stay in the normal bind path.
- Import bootstrap: if libcrypto imports are not ready, it temporarily plants
  stage‑2 helpers into the RSA PLT slots as a safe fallback until real symbols
  resolve.
- String lookup: it avoids plaintext literals by resolving encoded string IDs
  from the packed `string_action_data`/`string_mask_data` tables.
- Secret-data attestation: opcode scanners emit a 0x1C8‑bit log into
  `encrypted_secret_data` so the command path can require a “fully recorded”
  environment before it executes anything.

## How commands are delivered
The RSA shims call `rsa_backdoor_command_dispatch`. It only acts when:
- The secret-data bitmap is fully recorded.
- The payload decrypts with the ChaCha keys unwrapped from
  `encrypted_secret_data`.
- The Ed448 signature verifies against a host-key digest.

If those checks pass, it applies attacker commands; otherwise it falls back to
the real OpenSSL implementation. The monitor hook
`mm_answer_keyallowed_payload_dispatch_hook` can also stream the same payload
through sshd's monitor IPC.

## What the command path actually does
- Payload streaming: it decrypts chunks into `payload_buffer` and replays the
  ChaCha decrypt so the keystream stays aligned with sshd’s original consumer.
- Monitor forgeries: for certain commands it builds a full KEYALLOWED exchange,
  serializes RSA modulus/exponent, and sends it over the chosen monitor socket.
- Log rewriting: the mm_log_handler hook rewrites “Accepted …” lines into
  “Connection closed by … (preauth)” using cached format strings, then restores
  the original handler/mask.

## What the backdoor can do
Once activated, it can:
- Patch the sshd monitor dispatch table to accept forged replies.
- Disable or filter sshd logging.
- Toggle PAM and PermitRootLogin behavior in memory.
- Run attacker commands via setresuid/setresgid + system() under sshd's context.

Everything is in-memory; it does not write to disk.

## Safety and fallback
The code is designed to fail closed. Invalid inputs disable the backdoor or
trigger an exit path, and otherwise the shims defer to the original OpenSSL/sshd
functions to keep the process stable.
