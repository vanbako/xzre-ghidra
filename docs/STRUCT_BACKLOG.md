# Struct Backlog

Structs (and struct-like overlays) we still need to model cleanly in `metadata/xzre_types.json`. Track active work here just like the enum backlog so we avoid duplicating effort.

## Workflow
- Confirm the struct layout by reviewing the affected `xzregh/*.c` decompilation plus any helper headers/scripts (search for `field0_0x0`/`._N_M_` accesses that hint at missing metadata).
- Update `metadata/xzre_types.json` with the refined struct definition (and `metadata/xzre_locals.json` whenever locals/register temps need the new type).
- Run `./scripts/refresh_xzre_project.sh` (or `--check-only`) so Ghidra picks up the struct, rewrites the exported `.c` files, and validates that `ghidra_scripts/generated/xzre_autodoc.json` stays in sync.
- Note the outcome here (strike-through, notes, or follow-ups) plus bump the relevant entries in `docs/STRUCT_PROGRESS.md` when a struct receives a focused pass.

## Candidates

### `sensitive_data` host key table
- **Where it shows up:** `xzregh/105410_sshd_recon_bootstrap_sensitive_data.c`, `xzregh/1094A0_rsa_backdoor_command_dispatch.c`, `xzregh/108EA0_mm_answer_keyallowed_payload_dispatch_hook.c`.
- **Why it matters:** This struct carries the host key arrays used for Ed448 verification and command dispatch; without field names the decomp still uses raw offsets.
- **Reverse-engineering plan:** Map the host key arrays (`host_keys`, `host_pubkeys`, `host_certificates`) plus any counters or ancillary pointers surfaced by the recon/scoring helpers. Update `metadata/xzre_types.json` and any locals in `metadata/xzre_locals.json` so the exported C stops using `field0_0x0` arithmetic.
- **Status (2025-12-20):** Pending – `sensitive_data` still needs a typed layout in `metadata/xzre_types.json` so the host key tables export as named fields.

### `sshbuf` layout
- **Where it shows up:** `xzregh/107950_sshbuf_extract_ptr_and_len.c`, `xzregh/107920_sshbuf_is_negative_mpint.c`, `xzregh/107A20_sshd_find_forged_modulus_sshbuf.c`, `xzregh/108EA0_mm_answer_keyallowed_payload_dispatch_hook.c`.
- **Why it matters:** Many helpers compute data/size offsets by hand; modeling `sshbuf` will make pointer math and bounds checks readable.
- **Reverse-engineering plan:** Use the OpenSSH headers in `third_party/include/openssh` to define only the fields used by these helpers (data pointer, size, max_size, offset). Keep the definition minimal and validate the export via `./scripts/refresh_xzre_project.sh`.
- **Status (2025-12-20):** Pending – `sshbuf` is not modeled yet, so the helpers still rely on raw offset math.

### `sshkey` minimal view
- **Where it shows up:** `xzregh/107630_verify_ed448_signed_payload.c`, `xzregh/1094A0_rsa_backdoor_command_dispatch.c`, plus any host key tables inside `sensitive_data`.
- **Why it matters:** The Ed448 verification path and RSA hooks dereference key material; a minimal `sshkey` layout helps explain the digest/signature flow.
- **Reverse-engineering plan:** Import the OpenSSH `sshkey` layout from `third_party/include/openssh`, then trim to the fields referenced in decomp (key type + RSA/Ed25519 pointers). Update metadata so the code uses named members instead of offsets.
- **Status (2025-12-20):** Pending – `sshkey` still needs a minimal layout in `metadata/xzre_types.json` to avoid raw offset dereferences.
