#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
GHIDRA="${GHIDRA_HOME:-$HOME/tools/ghidra_11.4.2_PUBLIC}"
PROJECT_DIR="$ROOT_DIR/ghidra_projects"
PROJECT_NAME="xzre_ghidra"
OBJECT_PATH="$ROOT_DIR/xzre/liblzma_la-crc64-fast.o"
HEADER_PATH="$ROOT_DIR/ghidra_scripts/xzre_types_import_preprocessed.h"
SCRIPT_PATH="$ROOT_DIR/ghidra_scripts"
ARCHIVE_PATH="$PROJECT_DIR/${PROJECT_NAME}_portable.zip"

if [[ ! -x "$GHIDRA/support/analyzeHeadless" ]]; then
  echo "error: analyzeHeadless not found under \$GHIDRA ($GHIDRA)" >&2
  exit 1
fi

if [[ ! -f "$OBJECT_PATH" ]]; then
  echo "error: expected object file at $OBJECT_PATH" >&2
  exit 1
fi

if [[ ! -f "$HEADER_PATH" ]]; then
  echo "error: expected preprocessed header at $HEADER_PATH" >&2
  exit 1
fi

"$GHIDRA/support/analyzeHeadless" "$PROJECT_DIR" "$PROJECT_NAME" \
  -import "$OBJECT_PATH" \
  -overwrite \
  -scriptPath "$SCRIPT_PATH" \
  -postScript ImportXzreTypes.py "$HEADER_PATH" \
  -postScript RenameFromLinkerMap.py "$ROOT_DIR/xzre/xzre.lds.in" \
  -postScript ApplySignaturesFromHeader.py \
  -postScript FixAllParamStorage.py

"$GHIDRA/support/analyzeHeadless" "$PROJECT_DIR" "$PROJECT_NAME" \
  -process liblzma_la-crc64-fast.o \
  -noanalysis \
  -scriptPath "$SCRIPT_PATH" \
  -postScript ExportProjectArchive.py archive="$ARCHIVE_PATH"
