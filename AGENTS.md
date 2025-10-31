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

## Working With Ghidra
- Regenerate or update the project with headless Ghidra (11.4.2) installed at `~/tools/ghidra_11.4.2_PUBLIC`:
  ```bash
  ~/tools/ghidra_11.4.2_PUBLIC/support/analyzeHeadless ghidra_projects xzre_ghidra \
    -import xzre/liblzma_la-crc64-fast.o \
    -overwrite
  ```
  - Remove `-overwrite` if you want to keep the existing project unchanged.
  - Add `-analysisTimeoutPerFile <seconds>` or additional flags as your workflow requires.
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
