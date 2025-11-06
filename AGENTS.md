# Agent Onboarding – xzre Ghidra Project

## Project Purpose
- Centralize reverse-engineering artifacts for the `xzre` malware analysis effort.
- Maintain a headless Ghidra project (`xzre_ghidra`) sourced from the `liblzma_la-crc64-fast.o` object in `xzre/`.

## Key Locations
- `xzre/`: Original source, build scripts, and compiled objects from the xzre investigation; keep this upstream Git checkout untracked in this workspace (treat it as read-only and avoid staging it).
- `ghidra_projects/`: Workspace for Ghidra projects produced via headless runs.
  - `xzre_ghidra.gpr` / `xzre_ghidra.rep`: Ghidra project container and repository.
- `ghidra_projects/xzre_ghidra_portable.zip`: Exported archive containing the consumable project snapshot.
- `PROGRESS.md`: Rolling log for analysis milestones and outstanding follow-ups.

## Source of Truth for Reverse-Engineering Metadata
- Function documentation: `metadata/functions_autodoc.json` is the canonical store. Bootstrap it once with `scripts/build_autodoc_from_sources.py`; afterwards edit the JSON directly (Codex should update this file when refining names/descriptions). Do not hand-edit the derived files under `ghidra_scripts/generated/`.
- Signatures and locals: `metadata/xzre_locals.json` holds the current mapping and gets copied into place during refresh runs so the project and text dumps stay in sync. Regenerate from the upstream sources with `scripts/extract_local_variables.py` when new functions land in `xzre/xzre_code/`.
- Refresh loop: `./scripts/refresh_xzre_project.sh` performs `metadata → Ghidra project → xzregh/`. It copies the JSON metadata into `ghidra_scripts/generated/`, applies it in a headless run, exports the project archive, and mirrors the updated comments back into `xzregh/*.c`. Any manual edits should hit the metadata JSON first, then re-run the refresh.
- Verification: the refresh emits `ghidra_scripts/generated/xzre_autodoc.json` as a derived artifact; differences between it and `metadata/functions_autodoc.json` indicate that the project mutated comments that were not recorded in metadata.
- Codex workflow:
  1. Review the decomp in `xzregh/`.
  2. Update `metadata/functions_autodoc.json` (and `metadata/xzre_locals.json` when renaming locals/parameters) with the improved insight.
  3. Run `./scripts/refresh_xzre_project.sh` to apply the metadata to Ghidra and regenerate the text dumps.

## Working With Ghidra
- Refresh the project with the bundled helper (runs the import, replays header types/signatures, and exports the portable snapshot so the System V calling convention fix is always applied):
  ```bash
  ./scripts/refresh_xzre_project.sh
  ```
  - The script assumes Ghidra lives at `~/tools/ghidra_11.4.2_PUBLIC`. Override with `GHIDRA_HOME=/path/to/ghidra ./scripts/refresh_xzre_project.sh` if needed.
  - Function names get restored via `RenameFromLinkerMap.py` on every refresh before signatures are re-applied; if the renames are skipped, prototypes from `ApplySignaturesFromHeader.py` will no longer match the `.L`/`FUN_` symbols.
  - Each refresh now regenerates `ghidra_scripts/generated/xzre_locals.json` via `scripts/extract_local_variables.py` and post-runs `ApplyLocalsFromXzreSources.py`, which tries to push local variable names/types from `xzre/xzre_code` into the active program. When a function is absent from `liblzma_la-crc64-fast.o`, the script logs it as missing; this is expected until those routines (or matching symbol aliases) are imported.
- Produce a portable archive suitable for sharing or version control without committing the working `.rep` directory:
  ```bash
  ~/tools/ghidra_11.4.2_PUBLIC/support/analyzeHeadless ghidra_projects xzre_ghidra \
    -process liblzma_la-crc64-fast.o \
    -noanalysis \
    -scriptPath ghidra_scripts \
    -postScript ExportProjectArchive.py archive=ghidra_projects/xzre_ghidra_portable.zip
  ```
  - The custom `ExportProjectArchive.py` script zips the `.gpr` file and entire `.rep` directory into `xzre_ghidra_portable.zip`, keeping the repo clean while preserving a reproducible snapshot.
- Use `PROGRESS.md` to log any specialized scripts, exports, or follow-up tasks created during analysis.

## Updating the Progress Log
- Append a new entry at the top of `PROGRESS.md` after each session.
- Capture the date (`YYYY-MM-DD`), the action taken, the rationale, and the next intended step.
- Include links to generated reports or scripts when relevant so the next analyst can find them quickly.

## Next Steps for Analysts
- Review the imported program under `ghidra_projects/xzre_ghidra` and determine additional binaries or archives that should be brought into the workspace.
- Correlate findings with the sources in `xzre/` and document insights or triage queues in `PROGRESS.md`.

## Ghidra Signature Quirks
- Headless imports flatten pointer qualifiers, so `const T *` becomes `T *` in `FunctionDefinitionDataType` prototypes even though the header retained `const`.
- Struct and enum tags collapse to their typedef names (e.g., `struct sshbuf *` renders as `sshbuf *`, `enum SocketMode` as `SocketMode`).
- Unsigned integer aliases and OpenSSH typedefs normalize to Ghidra builtins (`unsigned int`→`uint`, `unsigned char *`→`uchar *`).
- Function-pointer parameters become pointers to auto-generated typedefs (e.g., `BOOL (*appender)(...)` shows up as `appender *`).
- Treat these differences as cosmetic when diffing signatures; re-running `ApplySignaturesFromHeader.py` keeps behavioral parity even though the display strings differ.
