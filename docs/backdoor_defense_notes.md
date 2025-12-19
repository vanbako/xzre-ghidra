# Backdoor Defensive Notes (High Level)

## Purpose
This document summarizes likely attacker outcomes and defensive signals based
on the current backdoor analysis. It avoids operational details.

## Responsible Use
This repository is intended for reverse engineering and defense. Avoid adding
operational steps or payload guidance that could enable misuse, and keep access
restricted to vetted analysts.

## Likely attacker outcomes (if they hold the Ed448 private key)
- Bypass sshd authentication by forging monitor replies.
- Disable or filter sshd logging to hide successful logins.
- Toggle in-memory sshd config such as PermitRootLogin and PAM.
- Execute commands via setresuid/setresgid + system() under sshd's context.
- Stage additional in-memory payloads using the same command channel.

## What the implant changes at runtime (defensive view)
- ld.so invokes `cpuid_ifunc_resolver_entry` during liblzma IFUNC resolution;
  the resolver bootstraps the loader and hook install.
- The loader walks ld.so link_map, parses ELF segments/relocations, and
  installs ld.so audit hooks plus RSA PLT shims.
- A secret-data attestation log is built from opcode scanners; command handling
  only proceeds once this log is complete.
- The sshd monitor dispatch table and mm_log_handler pointers are patched in
  memory and can be restored on failure.

## Host-based detection ideas
- Check for unexpected ld.so audit state in the sshd process (audit hooks set,
  l_audit_any_plt toggled, or altered _dl_audit pointers).
- Watch for sshd GOT/PLT entries for RSA_public_decrypt, EVP_PKEY_set1_RSA,
  or RSA_get0_key pointing outside libcrypto.
- Alert on sshd calling system(), setresuid(), or setresgid() in contexts where
  it normally would not.
- Look for log anomalies: "Connection closed by ... (preauth)" lines that
  coincide with otherwise successful auth, or log masks being forced to 0xff.
- Detect mm_answer_* handler pointers changed from their expected text ranges.

## Network and behavior signals
- Monitor traffic on sshd's monitor sockets that does not match known request
  shapes, especially large or repeated payload chunks.
- Unexpected RSA operations with payload-like modulus sizes or patterns.

## Mitigations and hardening
- Rebuild or replace liblzma and libcrypto from trusted sources; verify package
  signatures and hashes.
- Restart sshd after remediation so in-memory hooks are cleared.
- Use process integrity checks (GOT/PLT validation, text-range verification)
  for sshd and liblzma in production.
- Use OS auditing (auditd/eBPF) to flag sshd execs or privilege changes.
- Limit sshd's ability to execute external commands where possible.

## Incident response notes
- Capture process memory and mappings for sshd before restart to preserve
  evidence of ld.so hooks, GOT patches, and monitor table rewrites.
- Correlate authentication logs with system call traces to spot forged replies.
