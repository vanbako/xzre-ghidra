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
TYPES_SOURCE="$META_DIR/xzre_types.json"
TYPES_HELPER="$ROOT_DIR/scripts/manage_types_metadata.py"
XZREGH_TYPES="$ROOT_DIR/xzregh/xzre_types.h"
TYPE_DOCS_SOURCE="$META_DIR/type_docs.json"
LINKER_MAP_JSON="$META_DIR/linker_map.json"

if [[ ! -x "$GHIDRA/support/analyzeHeadless" ]]; then
  echo "error: analyzeHeadless not found under \$GHIDRA ($GHIDRA)" >&2
  exit 1
fi

if [[ ! -f "$OBJECT_PATH" ]]; then
  echo "error: expected object file at $OBJECT_PATH" >&2
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

if [[ ! -f "$TYPES_SOURCE" ]]; then
  echo "error: expected type metadata at $TYPES_SOURCE" >&2
  exit 1
fi

if [[ ! -f "$TYPES_HELPER" ]]; then
  echo "error: expected type metadata helper at $TYPES_HELPER" >&2
  exit 1
fi

if [[ ! -f "$LINKER_MAP_JSON" ]]; then
  echo "error: expected linker map metadata at $LINKER_MAP_JSON" >&2
  exit 1
fi

TYPE_DOCS_ARGS=()
TYPE_DOCS_POST=()
if [[ -f "$TYPE_DOCS_SOURCE" ]]; then
  TYPE_DOCS_ARGS=(--docs "$TYPE_DOCS_SOURCE")
  TYPE_DOCS_POST=(-postScript ApplyTypeDocs.py "docs=$TYPE_DOCS_SOURCE")
else
  echo "warning: type documentation metadata missing at $TYPE_DOCS_SOURCE; type comments will be skipped." >&2
fi

python3 "$TYPES_HELPER" render --json "$TYPES_SOURCE" --output "$HEADER_PATH" --skip-preamble "${TYPE_DOCS_ARGS[@]}"
python3 "$TYPES_HELPER" render --json "$TYPES_SOURCE" --output "$XZREGH_TYPES" "${TYPE_DOCS_ARGS[@]}"

if [[ ! -f "$HEADER_PATH" ]]; then
  echo "error: failed to render preprocessed header at $HEADER_PATH" >&2
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
  -postScript RenameFromLinkerMap.py "$LINKER_MAP_JSON" \
  -postScript ApplySignaturesFromHeader.py \
  -postScript InstallEnumEquates.py "$HEADER_PATH" \
  -postScript FixAllParamStorage.py \
  "${TYPE_DOCS_POST[@]}"

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
