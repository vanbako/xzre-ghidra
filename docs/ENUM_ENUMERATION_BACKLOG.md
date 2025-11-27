# Enum Backlog

Working queue for enums we want represented in `metadata/xzre_types.json`. Update this file as items land (strike-through or add notes) so we can take them one at a time.

## Workflow
- Add/adjust the enum definition inside `metadata/xzre_types.json` (and rerun `scripts/manage_types_metadata.py` if needed).
- If any locals/fields change types, update `metadata/xzre_locals.json` so the refresh can rewrite the decomp.
- Run `./scripts/refresh_xzre_project.sh` (or `--check-only` first) to regenerate `xzregh/*.c` plus the Ghidra artifacts.
- Inspect `ghidra_scripts/generated/xzre_autodoc.json` and the refreshed sources for regressions before moving to the next enum.

## Candidates

### ~~`payload_stream_state_t`~~
- **Done 2025-11-27:** Added `payload_stream_state_t` to `metadata/xzre_types.json`, updated `global_context_t.payload_state` plus the affected locals to use it, and reran the refresh pipeline so `check_backdoor_state`/`mm_answer_keyallowed_hook` now print the symbolic state names.

### `payload_command_type_t`
- **Where:** `xzregh/108EA0_mm_answer_keyallowed_hook.c:23` (`payload_type`), and `sshd_payload_ctx_t::command_type` (`xzregh/xzre_types.h:985`).
- **Why:** Only values 1/2/3 are valid (authpayload stash, keyverify reply, system exec). An enum makes the handler branches self-documenting and opens the door for future validation helpers.
- **Steps:** Define the enum near `sshd_payload_ctx_t` in `metadata/xzre_types.json`, update `command_type` plus the locals in `metadata/xzre_locals.json`, refresh, and confirm the exported C now shows the symbolic names.

### `monitor_reqtype_t`
- **Where:** `xzregh/107D50_sshd_patch_variables.c:16-69`, `xzregh/1094A0_run_backdoor_commands.c:443-455`, and `sshd_ctx_t` fields at `xzregh/xzre_types.h:1005`/`:1010`.
- **Why:** These variables always carry OpenSSH `MONITOR_REQ_*` opcodes. Importing the upstream enum (or mirroring it locally) avoids the hand-rolled `+1` offsets and clarifies when we’re overriding dispatch table slots.
- **Steps:** Add a typedef (wrapping `enum monitor_reqtype` from `third_party/include/openssh/monitor.h` or inlining the needed constants), switch the `sshd_ctx_t` members and function parameters to the new type, update locals metadata, then refresh to ensure the monitor hooks show the named constants.

### `audit_pattern_state_t`
- **Where:** `xzregh/104AE0_find_link_map_l_audit_any_plt_bitmask.c:34-177` (`pattern_state` variable inside the LEA/MOV/TEST scanner).
- **Why:** The scanner cycles through exactly three phases. Replacing the raw integer with an enum (`AUDIT_PAT_EXPECT_LEA`, `AUDIT_PAT_EXPECT_MOV`, `AUDIT_PAT_EXPECT_TEST`) makes the control flow obvious and documents the intended progression for future tweaks.
- **Steps:** Add the enum to `metadata/xzre_types.json`, update `metadata/xzre_locals.json` for the `pattern_state` local, run the refresh, and verify the exported helper now prints the symbolic state names in comments/logs as needed.
