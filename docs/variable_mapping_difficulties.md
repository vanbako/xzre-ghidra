# Variable Mapping Difficulties

## Automation Artifacts
- `scripts/map_locals.py` orchestrates the end-to-end comparison. It extracts source locals with usage sites via Clang, drives `DumpFunctionLocals.py` headlessly against `ghidra_projects/xzre_ghidra`, and writes the consolidated results to `reports/variable_mapping_report.json`.
- `ghidra_scripts/DumpFunctionLocals.py` collects decompiler locals (names, storage, use addresses, call-site indices, and return participation) so the matcher can reason about register-vs-stack placements. The script also emits per-run diagnostics such as “Function not found” when the binary does not contain the requested symbol.
- `ghidra_scripts/ApplyMappedLocals.py` now consumes the JSON report directly, renaming the confident matches (including register-only locals) by querying the decompiler’s `HighFunction` symbol map.
- `reports/variable_mapping_report.json` contains the latest run for the first five `xzre` helpers: `backdoor_entry`, `backdoor_symbind64`, `c_memmove`, `c_strlen`, and `c_strnlen`.

## Backdoor Function Audit
- Only two helpers in `xzre_locals.json` carry the `backdoor_` prefix (`backdoor_entry`, `backdoor_symbind64`). The latest run targeted just these routines via `python scripts/map_locals.py --functions backdoor_entry backdoor_symbind64`.
- `backdoor_entry` (`xzre/xzre_code/backdoor_entry.c`): `state`, `b`, `c`, and `d` align with stack slots; the final scalar `a` remains unmatched because it stays in registers for the entire function body, so no stack or SSA bucket survives for the rename.
- `backdoor_symbind64` (`xzre/xzre_code/backdoor_symbind64.c`): still absent from `liblzma_la-crc64-fast.o`. The pipeline records the miss and lists all source locals as unmatched until the corresponding object (or an equivalent thunk) is imported.

## Project-Wide Matches
- Running `python scripts/map_locals.py --limit 100` covered the full set of 33 `xzre` functions present in `xzre_locals.json`. Twenty-four functions produced at least one local-variable match in the current `liblzma_la-crc64-fast.o` import; the remainder either lack locals in the C sources (“helper” wrappers) or do not exist in the object yet (for example, `backdoor_symbind64`).
- `reports/variable_mapping_report.json` now captures the complete mapping set. `fake_lzma_free`, `init_elf_entry_ctx`, `update_cpuid_got_index`, and `update_got_offset` declare no locals in the sources, so they naturally report “no data” on both sides.
- Many of the larger routines (`elf_parse`, `decrypt_payload_message`, `extract_payload_message`, `rsa_key_hash`, `sshd_patch_variables`) rely on fallback matches because Ghidra’s decompiler collapses composite locals into wider scalars or pointer-to-array blobs. These cases are still linked by storage/usage similarity, and each entry is annotated with the type discrepancy so analysts know to validate before renaming inside Ghidra.
- `scripts/map_locals.py` now normalises additional family typedefs (`size_t`, `undefined8`, etc.) so common pointer/integer aliases line up with Ghidra’s canonical types. When strict matching fails, the scorer falls back to storage/usage-aware matches, noting where the types diverge.
- Register-only locals are matched heuristically by correlating the Clang AST call/return sites with the decompiler’s call arguments; when the signal is clear (single candidate, consistent usage counts), the match is emitted without a warning and `ApplyMappedLocals.py` will rename the corresponding register symbol automatically.

## Five-Function Snapshot
- `backdoor_entry` (`xzre/xzre_code/backdoor_entry.c`): matched `state` plus `b/c/d` to `local_48/local_50/local_54`, but `a` remains unresolved because the optimizer kept it in registers with no dedicated stack slot.
- `backdoor_symbind64` (`xzre/xzre_code/backdoor_symbind64.c`): missing from `liblzma_la-crc64-fast.o`, so no Ghidra locals were available to compare. The runner logs the miss in the headless output.
- `c_memmove` (`xzre/xzre_code/c_memmove.c`): both lexical `curr` variables map to the same RCX register in the object. The matcher binds the backward-scan copy to `sVar2` and the forward copy to `lVar1`, emitting a fallback note because one side surfaced as `long`.
- `c_strlen` (`xzre/xzre_code/c_strlen.c`): the alias map (`ssize_t` → `long`) allows a clean match between `len` and `lVar1`.
- `c_strnlen` (`xzre/xzre_code/c_strnlen.c`): the only Ghidra local (`sVar1`) reports `size_t` while the source uses `ssize_t`. The fallback heuristic matches them by shared RCX usage and records the type disagreement.

## Mapping Difficulties & Mitigations
- **Missing Functions**: When the object omits a helper (e.g., `backdoor_symbind64`), there is nothing to decompile. The headless run now records the miss and the report keeps the source locals under `unmatched_source` so analysts know to import additional objects or rename thunks before retrying.
- **Type Alias Drift**: Source typedefs (`u32`, `ssize_t`, etc.) rarely survive intact in Ghidra (`uint`, `long`). Normalizing the strings inside `map_locals.py` (see `_normalize_type`) closes most gaps; the script also flags residual mismatches so the alias table can be extended.
- **Composite-to-Scalar Collapses**: In complex routines (notably `elf_parse`, `decrypt_payload_message`, `extract_payload_message`, `rsa_key_hash`, `sshd_patch_variables`) the optimizer stores structs or arrays in temporaries that Ghidra renders as wide scalars or pointer arrays. The matcher leans on storage overlap to suggest names and leaves a note when the type strings diverge, reminding reviewers to sanity-check the rename.
- **Register-Only Locals**: Register temporaries now get matched whenever their call/return footprint aligns with the source (for example, `c_strnlen::len` now maps onto `sVar1`). Outliers that never escape the return register (notably `backdoor_entry::a`) still surface as unmatched so analysts can decide whether a manual rename is worthwhile.
- **Register Reuse / Variable Splitting**: Optimized builds frequently allocate one register to multiple lexical locals. The matcher groups any extra Ghidra locals that share a normalized type with an already-matched source variable and proposes suffixes (`foo`, `foo_1`, …). When the decompiler merges multiple source locals into one slot (the two `curr` instances in `c_memmove`), both source declarations remain visible in the report so analysts can manually disambiguate.
- **Usage Coordinate Recovery**: Clang’s JSON AST reports byte offsets rather than line numbers for `DeclRefExpr` nodes. The source extractor backfills line numbers by replaying the offsets against the file contents, yielding the `uses` lists in the report without demanding DWARF.
- **Nonnull Type Matches**: Some cases (e.g., `c_strnlen`) still require best-effort matches where the type strings diverge but storage and usage align. These are captured with explicit fallback notes so that analysts can double-check the suggestion before bulk-renaming locals inside Ghidra.

Run `python scripts/map_locals.py` after refreshing the project to regenerate the comparison artifacts and extend the alias table or heuristics as new counter-examples surface.
