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
META_DIR="$ROOT_DIR/metadata"
AUTODOC_SOURCE="$META_DIR/functions_autodoc.json"
AUTODOC_GENERATED="$SCRIPT_PATH/generated/xzre_autodoc_generated.json"
AUTODOC_EXPORT="$SCRIPT_PATH/generated/xzre_autodoc.json"
LOCALS_SOURCE="$META_DIR/xzre_locals.json"
LOCALS_GENERATED="$SCRIPT_PATH/generated/xzre_locals.json"

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

if [[ ! -f "$AUTODOC_SOURCE" ]]; then
  echo "error: expected AutoDoc metadata at $AUTODOC_SOURCE" >&2
  exit 1
fi

if [[ ! -f "$LOCALS_SOURCE" ]]; then
  echo "error: expected locals metadata at $LOCALS_SOURCE" >&2
  exit 1
fi

mkdir -p "$SCRIPT_PATH/generated"
cp "$AUTODOC_SOURCE" "$AUTODOC_GENERATED"
cp "$LOCALS_SOURCE" "$LOCALS_GENERATED"

"$GHIDRA/support/analyzeHeadless" "$PROJECT_DIR" "$PROJECT_NAME" \
  -import "$OBJECT_PATH" \
  -overwrite \
  -scriptPath "$SCRIPT_PATH" \
  -postScript ImportXzreTypes.py "$HEADER_PATH" \
  -postScript RenameFromLinkerMap.py "$ROOT_DIR/xzre/xzre.lds.in" \
  -postScript ApplySignaturesFromHeader.py \
  -postScript InstallEnumEquates.py "$HEADER_PATH" \
  -postScript FixAllParamStorage.py

"$GHIDRA/support/analyzeHeadless" "$PROJECT_DIR" "$PROJECT_NAME" \
  -process liblzma_la-crc64-fast.o \
  -noanalysis \
  -scriptPath "$SCRIPT_PATH" \
  -postScript ApplyAutoDocComments.py comments="$AUTODOC_GENERATED" \
  -postScript ExportAutoDocComments.py output="$AUTODOC_EXPORT" \
  -postScript ExportProjectArchive.py archive="$ARCHIVE_PATH"

if ! cmp -s "$AUTODOC_SOURCE" "$AUTODOC_EXPORT"; then
  echo "warning: exported AutoDoc comments differ from metadata/functions_autodoc.json" >&2
fi

python3 "$ROOT_DIR/scripts/apply_ghidra_comments_to_decomp.py" \
  --comments-json "$AUTODOC_EXPORT" \
  --xzregh-dir "$ROOT_DIR/xzregh"
