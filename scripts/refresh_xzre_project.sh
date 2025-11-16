#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat <<'EOF'
Usage: ./scripts/refresh_xzre_project.sh [--check-only]

Refreshes the headless Ghidra project, reapplies metadata, exports the portable
archive, and mirrors comments into xzregh/*.c. With --check-only, all work is
performed inside a temporary project so the repository remains untouched.
EOF
}

CHECK_ONLY=0
while [[ $# -gt 0 ]]; do
  case "$1" in
    --check-only)
      CHECK_ONLY=1
      shift
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      echo "error: unknown argument: $1" >&2
      usage >&2
      exit 1
      ;;
  esac
done

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
GHIDRA="${GHIDRA_HOME:-$HOME/tools/ghidra_11.4.2_PUBLIC}"
PROJECT_PARENT="$ROOT_DIR/ghidra_projects"
PROJECT_DIR="$PROJECT_PARENT"
PROJECT_NAME="xzre_ghidra"
OBJECT_PATH="$ROOT_DIR/xzre/liblzma_la-crc64-fast.o"
SCRIPT_PATH="$ROOT_DIR/ghidra_scripts"
HEADER_PATH="$SCRIPT_PATH/xzre_types_import_preprocessed.h"
XZREGH_TYPES="$ROOT_DIR/xzregh/xzre_types.h"
XZREGH_EXPORT_DIR="$ROOT_DIR/xzregh"
GENERATED_DIR="$SCRIPT_PATH/generated"
ARCHIVE_PATH="$PROJECT_DIR/${PROJECT_NAME}_portable.zip"

if [[ "$CHECK_ONLY" -eq 1 ]]; then
  CHECK_TMP="$(mktemp -d "${TMPDIR:-/tmp}/xzre-ghidra-check.XXXXXX")"
  trap 'rm -rf "$CHECK_TMP"' EXIT
  PROJECT_DIR="$CHECK_TMP/ghidra_projects"
  mkdir -p "$PROJECT_DIR"
  PROJECT_NAME="xzre_ghidra_check"
  HEADER_PATH="$CHECK_TMP/xzre_types_import_preprocessed.h"
  XZREGH_TYPES="$CHECK_TMP/xzre_types.h"
  XZREGH_EXPORT_DIR="$CHECK_TMP/xzregh"
  GENERATED_DIR="$CHECK_TMP/generated"
  ARCHIVE_PATH="$CHECK_TMP/${PROJECT_NAME}_portable.zip"
  echo "[check-only] running refresh in sandbox: $CHECK_TMP"
fi

META_DIR="$ROOT_DIR/metadata"
AUTODOC_SOURCE="$META_DIR/functions_autodoc.json"
AUTODOC_GENERATED="$GENERATED_DIR/xzre_autodoc_generated.json"
AUTODOC_EXPORT="$GENERATED_DIR/xzre_autodoc.json"
LOCALS_SOURCE="$META_DIR/xzre_locals.json"
LOCALS_GENERATED="$GENERATED_DIR/xzre_locals.json"
TYPES_SOURCE="$META_DIR/xzre_types.json"
TYPE_DOCS_SOURCE="$META_DIR/type_docs.json"
TYPES_HELPER="$ROOT_DIR/scripts/manage_types_metadata.py"
LINKER_MAP_JSON="$META_DIR/linker_map.json"

mkdir -p "$PROJECT_DIR"
mkdir -p "$(dirname "$HEADER_PATH")"
mkdir -p "$(dirname "$XZREGH_TYPES")"
mkdir -p "$XZREGH_EXPORT_DIR"
mkdir -p "$GENERATED_DIR"
mkdir -p "$(dirname "$ARCHIVE_PATH")"

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
  -postScript ApplyLocalsFromXzreSources.py "map=$LOCALS_GENERATED" \
  "${TYPE_DOCS_POST[@]}"

"$GHIDRA/support/analyzeHeadless" "$PROJECT_DIR" "$PROJECT_NAME" \
  -process liblzma_la-crc64-fast.o \
  -noanalysis \
  -scriptPath "$SCRIPT_PATH" \
  -postScript ApplyAutoDocComments.py comments="$AUTODOC_GENERATED" \
  -postScript ExportAutoDocComments.py output="$AUTODOC_EXPORT" \
  -postScript ExportProjectArchive.py archive="$ARCHIVE_PATH"

echo "Clearing existing decomp files under $XZREGH_EXPORT_DIR"
find "$XZREGH_EXPORT_DIR" -maxdepth 1 -type f -name '*.c' -delete

"$GHIDRA/support/analyzeHeadless" "$PROJECT_DIR" "$PROJECT_NAME" \
  -process liblzma_la-crc64-fast.o \
  -noanalysis \
  -scriptPath "$SCRIPT_PATH" \
  -postScript ExportFunctionDecompilations.py "out=$XZREGH_EXPORT_DIR" "types=$XZREGH_TYPES"

python3 "$ROOT_DIR/scripts/postprocess_register_temps.py" \
  --metadata "$LOCALS_SOURCE" \
  --xzregh-dir "$XZREGH_EXPORT_DIR"

RENAME_REPORT="$GENERATED_DIR/locals_rename_report.txt"
python3 "$ROOT_DIR/scripts/check_locals_renames.py" --output "$RENAME_REPORT" || \
  echo "warning: locals rename verification reported issues. See $RENAME_REPORT." >&2

if ! cmp -s "$AUTODOC_SOURCE" "$AUTODOC_EXPORT"; then
  echo "warning: exported AutoDoc comments differ from metadata/functions_autodoc.json" >&2
  if [[ "$CHECK_ONLY" -eq 1 ]]; then
    echo "[check-only] diff between metadata/functions_autodoc.json and exported comments:" >&2
    diff -u "$AUTODOC_SOURCE" "$AUTODOC_EXPORT" >&2 || true
  fi
fi

if [[ "$CHECK_ONLY" -eq 0 ]]; then
python3 "$ROOT_DIR/scripts/apply_ghidra_comments_to_decomp.py" \
  --comments-json "$AUTODOC_EXPORT" \
  --xzregh-dir "$XZREGH_EXPORT_DIR" \
  --ensure-include '#include "xzre_types.h"'
else
  echo "[check-only] skipped applying comments to xzregh; temporary artifacts removed on exit."
fi

if [[ "$CHECK_ONLY" -eq 1 ]]; then
  echo "[check-only] Ghidra refresh completed without touching ghidra_projects/ or xzregh/."
else
  echo "Refresh complete. Portable archive updated at $ARCHIVE_PATH"
fi
