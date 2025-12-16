# Struct Backlog

Structs (and struct-like overlays) we still need to model cleanly in `metadata/xzre_types.json`. Track active work here just like the enum backlog so we avoid duplicating effort.

## Workflow
- Confirm the struct layout by reviewing the affected `xzregh/*.c` decompilation plus any helper headers/scripts (search for `field0_0x0`/`._N_M_` accesses that hint at missing metadata).
- Update `metadata/xzre_types.json` with the refined struct definition (and `metadata/xzre_locals.json` whenever locals/register temps need the new type).
- Run `./scripts/refresh_xzre_project.sh` (or `--check-only`) so Ghidra picks up the struct, rewrites the exported `.c` files, and validates that `ghidra_scripts/generated/xzre_autodoc.json` stays in sync.
- Note the outcome here (strike-through, notes, or follow-ups) plus bump the relevant entries in `docs/STRUCT_PROGRESS.md` when a struct receives a focused pass.

## Candidates

### `key_payload_t` header view
- **Where it shows up:** `xzregh/108D50_decrypt_payload_message.c:57-77` and `xzregh/1094A0_run_backdoor_commands.c:120-318` still reference `payload->field0_0x0` / `encrypted_payload.field0_0x0` with raw `_N_M_` slices for the stride/index/bias nonce, encrypted-body length, and command flag bytes.
- **Why it matters:** Those chunks are really `{backdoor_payload_hdr_t header; u16 encrypted_body_length; u8 encrypted_body[];}`. Without a typed overlay the payload pipeline is unreadable and prone to off-by-one mistakes when copying lengths.
- **Reverse-engineering plan:** Revisit the RSA hook call sites and ChaCha decrypt helper to document the exact layout (header, size prefix, ciphertext). Update the struct definition inside `metadata/xzre_types.json` (or introduce a dedicated `key_payload_chunk_t` union) and nudge any locals in `metadata/xzre_locals.json` to the new type so the refresh exports `encrypted_payload.header`/`encrypted_payload.body` instead of `field0_0x0.*`.
- **Status (2025-11-27):** Completed – `metadata/xzre_types.json` now defines `key_payload_t` as `{header, encrypted_body_length, encrypted_body[1]}` plus the flattened `backdoor_payload_hdr_t`, and the refresh rewrote `xzregh/108D50*.c`/`1094A0*.c` to use the named fields and typed ciphertext tail. Leaving the entry in place for historical context; future payload work should jump to `sshd_offsets_t`.

### `sshd_offsets_t` packed indexes
- **Where it shows up:** `xzregh/107A20_sshd_get_sshbuf.c:41-63`, `xzregh/107950_sshbuf_extract.c:31-63`, and `xzregh/1094A0_run_backdoor_commands.c:250-326` keep poking `*(byte *)((long)&(ctx->sshd_offsets).field0_0x0 + N)` to recover the pkex slot, sshbuf data/size qword indexes, etc.
- **Why it matters:** The runtime clearly stores a four-byte struct of signed qword indexes (pkex slot, kex qword, sshbuf data index, sshbuf size index). Modeling it as named fields (or tiny unions for the per-subsystem offsets) would make the accessor helpers straightforward and stop the pointer arithmetic from popping back up after every refresh.
- **Reverse-engineering plan:** Map the byte order once (refer to the OpenSSH `monitor` layout plus the `sshd_offsets_fields_t` helper) and update `metadata/xzre_types.json` so `sshd_offsets_t` exposes meaningful members instead of the `field0_0x0` union. Follow up by ensuring `metadata/xzre_locals.json` tags any locals/temps that expect the structured view so the refresh emits the real field names.
- **Status (2025-12-15):** Completed – `metadata/xzre_types.json` now models `sshd_offsets_t` as a named union with signed index bytes (kex sshbuf qword index, monitor pkex-table dword index, sshbuf data/size qword indices) plus a `raw_value` overlay; after a refresh the exported helpers stop relying on `field0_0x0` pointer arithmetic.

### `dasm_ctx_t.prefix` overlays
- **Where it shows up:** Instruction scanners such as `xzregh/104AE0_find_link_map_l_audit_any_plt_bitmask.c:76-192`, `xzregh/104EE0_find_link_map_l_audit_any_plt.c:65-145`, and `xzregh/103680_sshd_get_sensitive_data_address_via_xcalloc.c:74` read `insn_ctx._40_4_`, `insn_ctx.prefix._15_1_`, etc. to decode ModRM/REX bits.
- **Why it matters:** The decoder already has a `dasm_ctx_t` structure; we just need to flesh out the prefix state so those helpers can refer to named fields (e.g., `ctx.prefix.decoded.modrm.breakdown.modrm_reg`). Doing so will also shrink the brittle `_0_4_` offsets that break whenever we add padding.
- **Reverse-engineering plan:** Use the existing `dasm_ctx_t` definition as a base, expand `x86_prefix_fields_t`/`x86_modrm_info_t` with the missing members referenced by the scanners, and update the metadata so the exported code stops using raw offsets. Re-run the refresh to verify the LEA/MOV/TEST state machine reads as idiomatic C.
- **Status (2025-12-16):** Completed – expanded `x86_prefix_state_t` with `flags_u32` plus a byte-level `modrm_bytes` overlay (REX/ModRM fields) so the exported scanners use `prefix.flags_u32`/`prefix.modrm_bytes.modrm_*` instead of `prefix._N_M_` slices; removed the now-obsolete locals postprocess rewrites and reran `./scripts/refresh_xzre_project.sh` to confirm the updated names land cleanly.

### Instruction-search register bitmaps
- **Where it shows up:** `xzregh/104EE0_find_link_map_l_audit_any_plt.c:65-145` manipulates `mask_register_bitmap._0_3_`, `output_register_bitmap._0_2_`, `search_ctx.offset_to_match._0_4_`, etc., suggesting these locals are really small structs/bitfields the matcher expects.
- **Why it matters:** These helper structs carry the register filters and match offsets throughout the three-stage scan; modeling them explicitly will clarify which registers are being tracked and reduce mistakes when adding new scan states.
- **Reverse-engineering plan:** Inspect `instruction_search_ctx_t` and the helpers in `xzregh/104AE0*` to infer the layout (likely `{u32 bitmap; u8 mask_reg; u8 pointer_reg; ...}`). Capture that in `metadata/xzre_types.json`, refresh the project, and confirm that the exported code now reads `search_ctx->offset_to_match.displacement` (or similar) instead of `_0_4_`.
- **Status (2025-12-16):** Completed – introduced `instruction_register_bitmap_t` + `instruction_search_offset_t` in `metadata/xzre_types.json`, retagged `instruction_search_ctx_t` to use them, and refreshed the project so `xzregh/104EE0_find_link_map_l_audit_any_plt.c`/`xzregh/104AE0_find_link_map_l_audit_any_plt_bitmask.c` now export `offset_to_match.dwords.offset` plus `bitmap.fields.{allowed_regs,reg_index}` instead of `_0_3_`/`_0_4_` slices.
