# xzre Ghidra Reverse Engineering Workspace

Reference workspace for the headless Ghidra project that captures the `xzre` malware artifacts. The repository keeps the metadata, automation, and exported decompilations in sync so every analyst (human or agentic) can iterate on the same source of truth without touching the upstream `xzre/` checkout.

## Mission & Scope
- Maintain a reproducible `xzre_ghidra` project imported from `xzre/liblzma_la-crc64-fast.o`.
- Treat the upstream sources under `xzre/` as read-only; all commentary, locals, and types live in `metadata/`.
- Propagate every metadata change through the headless pipeline so `ghidra_projects/`, the portable archive, and the `xzregh/*.c` text dumps stay aligned.
- Capture analyst decisions, helper scripts, and future work in `PROGRESS.md` to keep the hand-off friction low.

## Repository Tour
| Path | Role |
| --- | --- |
| `xzre/` | Upstream code and build tree from the investigation. Leave unmodified/untracked. |
| `metadata/` | Authoritative JSON for AutoDoc comments (`functions_autodoc.json`), locals (`xzre_locals.json`), typedefs (`xzre_types.json`), linker map (`linker_map.json`), and structured typedocs. |
| `notes/` | Scratch pads generated per function via `scripts/generate_function_stubs.py`; safe place for interim RE notes. |
| `ghidra_scripts/` | Jython helpers invoked during the refresh (renaming, signatures, locals, exports, archive creation). `ghidra_scripts/generated/` is rewritten by the pipeline—never edit it manually. |
| `ghidra_projects/` | Writable Ghidra working copy (`xzre_ghidra.gpr/.rep`) plus the shareable `xzre_ghidra_portable.zip`. |
| `xzregh/` | Textual decompilations emitted per function, kept in sync with the metadata and always including `xzre_types.h`. |
| `scripts/` | Python and shell automation for metadata editing, locals extraction, comment application, and the main refresh driver. |
| `docs/`, `AGENTS.md`, `PROGRESS.md` | High-level onboarding, collaboration log, and any long-form writeups. Add a new `PROGRESS.md` entry at the top after every session. |

## Reverse-Engineering Pipeline
1. **Prep metadata.**
   - Update function docs: `scripts/edit_autodoc.py <symbol>` or edit `metadata/functions_autodoc.json` directly for bulk changes.
   - Regenerate locals when upstream sources change: `scripts/extract_local_variables.py`.
   - Manage type coverage with `scripts/manage_types_metadata.py` plus `metadata/xzre_types.json`.
   - Optional: bootstrap new entries from upstream via `scripts/build_autodoc_from_sources.py`.
2. **Run the refresh loop.**
   - Use `./scripts/refresh_xzre_project.sh` (set `GHIDRA_HOME=/path/to/ghidra` if your install differs from the default `~/tools/ghidra_11.4.2_PUBLIC`).
   - The script performs: metadata sync → headless import → `RenameFromLinkerMap.py` (driven by `metadata/linker_map.json`) → ApplySignatures/AutoDoc/TypeDocs/Locals → regeneration of `ghidra_scripts/generated/*` → export of `ghidra_projects/xzre_ghidra_portable.zip` → register-temp post-processing (`scripts/postprocess_register_temps.py`) → sync of new comments back into `xzregh/*.c`.
   - Run `./scripts/refresh_xzre_project.sh --check-only` to validate metadata updates in a throwaway project without mutating the working `.rep` or decomp tree.
3. **Review and hand off.**
   - Inspect the updated `xzregh/*.c` files (and `ghidra_scripts/generated/xzre_autodoc.json`) to confirm the comments match the metadata. A diff between `metadata/functions_autodoc.json` and the generated file indicates manual edits happened somewhere other than the metadata store.
   - Distribute `ghidra_projects/xzre_ghidra_portable.zip` for consumers who need the full Ghidra project without the large `.rep` directory.
   - Record the work and next steps in `PROGRESS.md`, then assign or request the next function batch.

## Metadata & Comment Guardrails
- `metadata/functions_autodoc.json` and `metadata/xzre_locals.json` are the only sources that should be hand-edited. Everything under `ghidra_scripts/generated/` is derived—if it differs from metadata after a refresh, treat that as a regression and re-run the pipeline.
- Locals are harvested from both `xzre/xzre_code/` and the top-level `xzre/*.c` files. Missing functions are logged (expected when an object does not contain the symbol). Update `metadata/xzre_locals.json` when renaming locals/parameters so ApplyLocals can replay the new names. Use the optional `register_temps` array inside each entry to describe Ghidra-only temporaries (`bVar*`/`uVar*`); the refresh pipeline reads that data to rename and re-type the register temps inside the exported `.c`.
- When a function exists in the metadata but is absent from the currently imported object, set `"skip_locals": true` on that entry so the refresh pipeline skips it until the relevant binary is added. `scripts/extract_local_variables.py` preserves the flag across regenerations.
- `metadata/linker_map.json` decouples name restoration from the upstream linker script; keep it synchronized if we ingest new symbols.
- Type aliases live in `metadata/xzre_types.json`. The exported header (`xzregh/xzre_types.h`) is rebuilt by the refresh script so downstream decompilations always include the latest typedefs.

## Automation Highlights
- `scripts/generate_function_stubs.py --batch <handle>` seeds `notes/<symbol>.md` with the current autodoc text, locals, and TODOs. Pass `--force` to refresh an existing stub or `--function <symbol>` for one-offs.
- `scripts/apply_ghidra_comments_to_decomp.py` enforces the AutoDoc header and `#include "xzre_types.h"` inside every `xzregh/*.c` file after a refresh.
- `scripts/postprocess_register_temps.py` applies the `register_temps` metadata to the exported files (renaming Ghidra’s synthetic temps and guaranteeing everything uses `BOOL`). It runs automatically inside `refresh_xzre_project.sh`, so recording the mapping in the JSON is all that’s required.
- `ghidra_scripts/ExportFunctionDecompilations.py` writes the per-function files and can mirror `xzre_types.h` alongside the exports when invoked with `types=...`.
- `ghidra_scripts/ExportProjectArchive.py` zips the `.gpr` and `.rep` into `ghidra_projects/xzre_ghidra_portable.zip`, giving collaborators a clean artifact for import.
- Jython helpers such as `ApplyAutoDocComments.py`, `ApplyLocalsFromXzreSources.py`, `ApplySignaturesFromHeader.py`, and `RenameFromLinkerMap.py` are chained automatically during `refresh_xzre_project.sh`.

## Agentic Workflow & Collaboration
- **Start with `AGENTS.md`.** It contains the full onboarding plus expectations for metadata sources, runner scripts, and quick command references.
- **Batch handles.** When requesting work from another agent, refer to the predefined sets to keep prompts scoped:
  | Handle | Focus |
  | --- | --- |
  | `opco_patt` | Opcode scanners, disassembly helpers, instruction search utilities. |
  | `elf_mem` | ELF parsers, relocation walkers, allocator/TLS helpers. |
  | `sshd_recon` | SSHD discovery, sensitive-data scoring, mm_* hooks. |
  | `loader_rt` | Loader/runtime setup, GOT/audit hooks, shared library traversal. |
  | `crypto_cmd` | Crypto helpers, sshbuf serializers, secret-data staging, RSA/MM hooks. |
- **Recommended loop.** (1) Generate stubs for the batch you plan to attack. (2) Review the corresponding `xzregh/*.c` decompilations. (3) Promote finalized insights into `metadata/functions_autodoc.json`/`metadata/xzre_locals.json`. (4) Run the refresh script (with `--check-only` first if you just need validation). (5) Update `PROGRESS.md` with date, actions, rationale, and next steps.
- **Progress tracking.** Keep entries in reverse chronological order and include links or file paths to any generated artifacts/scripts so the next analyst can continue immediately.
- **Hand-offs.** Mention open questions or suspected bugs inside the relevant `notes/*.md` stub and summarize the state in `PROGRESS.md`. That context is what downstream agents rely on when they pull a batch.

## Troubleshooting & Tips
- Refresh fails under Jython if file handles include `encoding=` kwargs—confirm scripts only use `codecs.open()`; the repo already reflects this fix.
- Missing functions in `ApplyLocalsFromXzreSources.py` warnings typically mean the symbol is absent from `liblzma_la-crc64-fast.o`; log it but continue.
- Always diff `metadata/functions_autodoc.json` before and after a session. Untracked changes there mean your refresh did not run or comments were edited elsewhere.
- If you only need to inspect or share the latest decomp, use the text exports under `xzregh/` and the portable archive instead of the live `.rep`.

This README, `AGENTS.md`, and `PROGRESS.md` are the touchpoints for scaling the reverse-engineering effort across humans and AI operators. Keep them current, and the refresh pipeline will keep doing the heavy lifting.

## Attribution
- This workspace builds on public research from the [smx-smx/xzre](https://github.com/smx-smx/xzre) repository, whose published analysis and artifacts provided the starting knowledge base for the project.
