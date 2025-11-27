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

### ~~`payload_command_type_t`~~
- **Done 2025-11-27:** Added a `payload_command_type` enum (with a `payload_command_type_t` typedef) so `sshd_payload_ctx_t::command_type` and the `payload_type` temp in `mm_answer_keyallowed_hook` now use symbolic states. Updated `metadata/xzre_locals.json` so the state-machine comparisons render as `PAYLOAD_COMMAND_*` names after the refresh.

### ~~`monitor_reqtype_t`~~
- **Done 2025-11-27:** Mirrored OpenSSH’s monitor request enum into the metadata, retagged the `sshd_ctx_t` fields, `sshd_patch_variables` signature, and the `op_result` local in `run_backdoor_commands` to `monitor_reqtype_t`, then ran the refresh so the exported sources show `MONITOR_REQ_*` names instead of raw ints.

### ~~`audit_pattern_state_t`~~
- **Done 2025-11-27:** Added the three-state `audit_pattern_state_t` enum to `metadata/xzre_types.json`, retagged the `pattern_state` register temp in `metadata/xzre_locals.json`, and ran the refresh so `find_link_map_l_audit_any_plt_bitmask` now shows `audit_pattern_state_t pattern_state` instead of an untyped integer while exporting the new enum in `xzre_types.h`.
