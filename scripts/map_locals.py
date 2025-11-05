#!/usr/bin/env python3
"""
Compare local variables declared in the xzre sources with the variables recovered
by Ghidra for selected functions. The script dumps a report that highlights
matches, mismatches, and cases where multiple Ghidra locals appear to represent
the same source variable (handled via ``_1`` suffixes).
"""

import argparse
import json
import os
import re
import subprocess
import sys
from collections import defaultdict, OrderedDict
from dataclasses import dataclass, field
from typing import Any, Dict, Iterable, List, Optional, Sequence, Tuple

REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
XZRE_LOCALS_JSON = os.path.join(REPO_ROOT, "ghidra_scripts", "generated", "xzre_locals.json")
DEFAULT_PROJECT_DIR = os.path.join(REPO_ROOT, "ghidra_projects")
DEFAULT_PROJECT_NAME = "xzre_ghidra"
DEFAULT_BINARY = "liblzma_la-crc64-fast.o"
REPORT_DIR = os.path.join(REPO_ROOT, "reports")
GHIDRA_OUTPUT_JSON = os.path.join(REPO_ROOT, "reports", "ghidra_locals_dump.json")
MAPPING_REPORT_JSON = os.path.join(REPO_ROOT, "reports", "variable_mapping_report.json")

BASE_TYPE_SIZES = {
    "char": 1,
    "uchar": 1,
    "schar": 1,
    "byte": 1,
    "bool": 1,
    "short": 2,
    "ushort": 2,
    "int": 4,
    "uint": 4,
    "long": 8,
    "ulong": 8,
    "longlong": 8,
    "ulonglong": 8,
    "float": 4,
    "double": 8,
    "size_t": 8,
    "ssize_t": 8,
    "ptrdiff_t": 8,
}

EQUIVALENT_BASE_TYPES = {
    "int": {"int", "uint"},
    "uint": {"int", "uint"},
    "long": {"long", "ulong"},
    "ulong": {"long", "ulong"},
    "longlong": {"longlong", "ulonglong"},
    "ulonglong": {"longlong", "ulonglong"},
    "bool": {"bool", "int", "uint"},
    "size_t": {"size_t", "ulong"},
    "ssize_t": {"ssize_t", "long"},
}


class ExtractionError(RuntimeError):
    """Raised when Clang AST parsing fails."""


def _load_xzre_locals() -> OrderedDict:
    with open(XZRE_LOCALS_JSON, "r", encoding="utf-8") as infile:
        data = json.load(infile, object_pairs_hook=OrderedDict)
    return data


def _get_functions_from_args(data: OrderedDict, requested: Optional[Sequence[str]], limit: int) -> List[str]:
    if requested:
        missing = [name for name in requested if name not in data]
        if missing:
            raise SystemExit("Requested functions not found in source metadata: {}".format(", ".join(missing)))
        return list(requested[:limit])
    return list(list(data.keys())[:limit])


def _clang_ast_for_source(path: str) -> Dict:
    cmd = [
        "clang",
        "-std=gnu17",
        "-fsyntax-only",
        "-fno-color-diagnostics",
        "-w",
        "-I",
        os.path.join(REPO_ROOT, "xzre"),
        "-Xclang",
        "-ast-dump=json",
        path,
    ]
    proc = subprocess.run(
        cmd,
        check=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    if proc.stderr:
        sys.stderr.write(proc.stderr)
    try:
        return json.loads(proc.stdout)
    except json.JSONDecodeError as exc:
        raise ExtractionError("Failed to parse Clang AST for {}".format(path)) from exc


def _get_loc_file(loc: Dict) -> str:
    """
    Unwrap Clang's ``includedFrom`` stack to recover the originating filename.
    """
    if not isinstance(loc, dict):
        return ""
    if "includedFrom" in loc:
        return _get_loc_file(loc["includedFrom"])
    return loc.get("file", "") or ""


@dataclass
class SourceVariable:
    name: str
    type_str: str
    decl_offset: Optional[int]
    decl_line: Optional[int] = None
    use_offsets: List[int] = field(default_factory=list)
    use_lines: List[int] = field(default_factory=list)
    call_sites: List[Dict[str, Any]] = field(default_factory=list)
    returned: bool = False
    size_hint: Optional[int] = None

    def to_dict(self) -> Dict:
        normalized = _normalize_type(self.type_str)
        hint = self.size_hint
        if hint is None:
            hint = _size_hint_from_normalized(normalized)
        return {
            "name": self.name,
            "type": self.type_str,
            "decl_line": self.decl_line,
            "uses": sorted(self.use_lines),
            "call_sites": list(self.call_sites),
            "returned": self.returned,
            "size_hint": hint,
        }


def _build_line_index(text: str) -> List[int]:
    offsets = [0]
    for index, char in enumerate(text):
        if char == "\n":
            offsets.append(index + 1)
    offsets.append(len(text))
    return offsets


def _offset_to_line(offsets: List[int], offset: int) -> Tuple[int, int]:
    import bisect

    idx = max(bisect.bisect_right(offsets, offset) - 1, 0)
    line_no = idx + 1
    col_no = offset - offsets[idx] + 1
    return line_no, col_no


def _collect_function_locals(
    ast_root: Dict,
    function_name: str,
    abs_source: str,
    rel_source: str,
    line_index: List[int],
) -> List[SourceVariable]:
    """
    Inspect the AST and return the locals declared in *function_name*.
    """
    stack = [ast_root]
    locals_out: Dict[str, SourceVariable] = OrderedDict()
    target_node = None

    while stack:
        node = stack.pop()
        if isinstance(node, dict) and node.get("kind") == "FunctionDecl" and node.get("name") == function_name:
            node_file = _get_loc_file(node.get("loc", {}))
            if os.path.normpath(os.path.join(REPO_ROOT, node_file)) != os.path.normpath(abs_source):
                # Skip declarations brought in from headers.
                continue
            # Prefer the definition that actually carries a body.
            for child in node.get("inner") or []:
                if isinstance(child, dict) and child.get("kind") == "CompoundStmt":
                    target_node = child
                    break
            if target_node:
                break
        if isinstance(node, dict):
            stack.extend(node.get("inner") or [])
        elif isinstance(node, list):
            stack.extend(node)

    if target_node is None:
        raise ExtractionError("Did not find a body for {} in {}".format(function_name, rel_source))

    # Traverse the body to collect VarDecls and their uses.
    traversal_stack = [target_node]
    while traversal_stack:
        node = traversal_stack.pop()
        if isinstance(node, dict):
            kind = node.get("kind")
            if kind == "VarDecl":
                var_id = node.get("id")
                name = node.get("name")
                type_info = node.get("type") or {}
                type_str = type_info.get("qualType") or type_info.get("desugaredQualType") or ""
                loc = node.get("loc") or {}
                offset = loc.get("offset")
                decl_line = None
                if isinstance(offset, int):
                    decl_line = _offset_to_line(line_index, offset)[0]
                locals_out[var_id] = SourceVariable(
                    name=name or "",
                    type_str=type_str or "",
                    decl_offset=offset if isinstance(offset, int) else None,
                    decl_line=decl_line,
                )
                locals_out[var_id].size_hint = _size_hint_from_normalized(_normalize_type(type_str or ""))
            traversal_stack.extend(node.get("inner") or [])
        elif isinstance(node, list):
            traversal_stack.extend(node)

    traversal_stack = [target_node]
    while traversal_stack:
        node = traversal_stack.pop()
        if isinstance(node, dict):
            if node.get("kind") == "DeclRefExpr":
                ref = node.get("referencedDecl") or {}
                if ref.get("kind") == "VarDecl":
                    var_id = ref.get("id")
                    if var_id in locals_out:
                        begin = (node.get("range") or {}).get("begin") or {}
                        offset = begin.get("offset")
                        if isinstance(offset, int):
                            locals_out[var_id].use_offsets.append(offset)
            traversal_stack.extend(node.get("inner") or [])
        elif isinstance(node, list):
            traversal_stack.extend(node)

    _collect_usage_context(target_node, locals_out)

    for var in locals_out.values():
        seen_lines = set()
        for offset in var.use_offsets:
            line_no, _ = _offset_to_line(line_index, offset)
            seen_lines.add(line_no)
        var.use_lines = sorted(seen_lines)
    return list(locals_out.values())


def _collect_usage_context(body: Dict[str, Any], locals_out: Dict[str, SourceVariable]) -> None:
    stack: List[Any] = [body]
    while stack:
        node = stack.pop()
        if isinstance(node, dict):
            kind = node.get("kind")
            if kind == "CallExpr":
                callee = _extract_callee_name(node)
                inner = node.get("inner") or []
                for idx, child in enumerate(inner):
                    if idx == 0:
                        continue  # callee expression
                    arg_index = idx - 1
                    for var_id, addr_flag in _extract_var_refs(child):
                        var = locals_out.get(var_id)
                        if var is not None:
                            var.call_sites.append(
                                {
                                    "callee": callee,
                                    "arg_index": arg_index,
                                    "address_of": addr_flag,
                                }
                            )
            elif kind == "ReturnStmt":
                for var_id, _ in _extract_var_refs(node):
                    var = locals_out.get(var_id)
                    if var is not None:
                        var.returned = True
            stack.extend(node.get("inner") or [])
        elif isinstance(node, list):
            stack.extend(node)


def _extract_callee_name(call_node: Dict[str, Any]) -> Optional[str]:
    inner = call_node.get("inner") or []
    if not inner:
        return None
    node = inner[0]
    while isinstance(node, dict) and node.get("kind") in ("ImplicitCastExpr", "ParenExpr"):
        nested = node.get("inner") or []
        if not nested:
            break
        node = nested[0]
    if isinstance(node, dict) and node.get("kind") == "DeclRefExpr":
        ref = node.get("referencedDecl") or {}
        return ref.get("name")
    if isinstance(node, dict) and node.get("kind") == "MemberExpr":
        name = node.get("name")
        if name:
            return name
    return None


def _extract_var_refs(node: Any, address_of: bool = False) -> List[Tuple[str, bool]]:
    results: List[Tuple[str, bool]] = []
    if isinstance(node, dict):
        kind = node.get("kind")
        if kind == "UnaryOperator" and node.get("opcode") == "&":
            for child in node.get("inner") or []:
                results.extend(_extract_var_refs(child, True))
            return results
        if kind == "DeclRefExpr":
            ref = node.get("referencedDecl") or {}
            if ref.get("kind") == "VarDecl":
                var_id = ref.get("id")
                if var_id:
                    results.append((var_id, address_of))
            return results
        for child in node.get("inner") or []:
            results.extend(_extract_var_refs(child, address_of))
    elif isinstance(node, list):
        for child in node:
            results.extend(_extract_var_refs(child, address_of))
    return results


def _collect_source_metadata(functions: Iterable[str], mapping: OrderedDict) -> Dict[str, Dict]:
    grouped: Dict[str, List[str]] = defaultdict(list)
    for func in functions:
        entry = mapping.get(func)
        if not entry:
            continue
        grouped[entry["source"]].append(func)

    results: Dict[str, Dict] = {}
    for rel_source, func_list in grouped.items():
        abs_source = os.path.join(REPO_ROOT, rel_source)
        ast_root = _clang_ast_for_source(abs_source)
        with open(abs_source, "r", encoding="utf-8") as src_file:
            text = src_file.read()
        line_index = _build_line_index(text)
        for func_name in func_list:
            locals_list = _collect_function_locals(ast_root, func_name, abs_source, rel_source, line_index)
            results[func_name] = {
                "source": rel_source,
                "locals": [var.to_dict() for var in locals_list],
            }
    return results


def _normalize_type(type_str: Optional[str]) -> str:
    if not type_str:
        return ""
    normalized = type_str.strip().lower()
    replacements = [
        ("unsigned int", "uint"),
        ("unsigned char", "uchar"),
        ("unsigned long long", "ulonglong"),
        ("unsigned long", "ulong"),
        ("long long unsigned", "ulonglong"),
        ("long unsigned", "ulong"),
        ("const ", ""),
        (" volatile", ""),
        ("struct ", ""),
        ("enum ", ""),
        ("int *", "int*"),
        ("uint *", "uint*"),
    ]
    for search, repl in replacements:
        normalized = normalized.replace(search, repl)
    normalized = normalized.replace(" *", "*")
    normalized = normalized.replace("* ", "*")
    while "  " in normalized:
        normalized = normalized.replace("  ", " ")
    alias_map = {
        "u8": "uchar",
        "u16": "ushort",
        "u32": "uint",
        "u64": "ulonglong",
        "ssize_t": "long",
        "__ssize_t": "long",
        "__size_t": "size_t",
        "size_t": "ulong",
        "undefined8": "ulong",
        "undefined4": "uint",
        "undefined2": "ushort",
        "undefined1": "uchar",
        "long long": "longlong",
        "unsigned": "uint",
        "unsigned long long": "ulonglong",
        "unsigned long": "ulong",
        "unsigned int": "uint",
        "ulonglong": "ulonglong",
        "ulong": "ulong",
        "uint": "uint",
    }
    pointer_depth = 0
    while normalized.endswith("*"):
        pointer_depth += 1
        normalized = normalized[:-1].rstrip()
    array_suffix = ""
    if "[" in normalized and normalized.endswith("]"):
        base, array_suffix = normalized.split("[", 1)
        array_suffix = "[" + array_suffix
    else:
        base = normalized
    base = alias_map.get(base, base)
    normalized = base + ("*" * pointer_depth) + array_suffix
    return normalized


def _pointer_depth(type_str: str) -> int:
    return type_str.count("*")


def _base_type_name(normalized: str) -> str:
    base = normalized
    if "[" in base:
        base = base.split("[", 1)[0]
    base = base.rstrip("*")
    return base


def _size_hint_from_normalized(normalized: str) -> Optional[int]:
    if not normalized:
        return None
    pointer_depth = _pointer_depth(normalized)
    if pointer_depth > 0:
        return 8
    array_len = None
    match = re.search(r"\[(\d+)\]", normalized)
    if match:
        try:
            array_len = int(match.group(1))
        except Exception:
            array_len = None
    base = _base_type_name(normalized)
    base_size = BASE_TYPE_SIZES.get(base)
    if base_size is None:
        return None if array_len is None else base_size
    if array_len is None:
        return base_size
    return base_size * array_len


def _types_close(src_type: str, cand_type: str) -> bool:
    if not src_type or not cand_type:
        return False
    if src_type == cand_type:
        return True
    if _pointer_depth(src_type) != _pointer_depth(cand_type):
        return False
    src_base = _base_type_name(src_type)
    cand_base = _base_type_name(cand_type)
    if not src_base or not cand_base:
        return False
    if src_base == cand_base:
        return True
    return cand_base in EQUIVALENT_BASE_TYPES.get(src_base, set())


def _allocate_name(base: str, used: set) -> str:
    if base not in used:
        used.add(base)
        return base
    idx = 1
    while True:
        candidate = "{}_{}".format(base, idx)
        if candidate not in used:
            used.add(candidate)
            return candidate
        idx += 1


def _call_signature(entries: Optional[List[Dict[str, Any]]]) -> set:
    signature = set()
    if not entries:
        return signature
    for entry in entries:
        callee = entry.get("callee")
        arg_index = entry.get("arg_index")
        signature.add((callee, arg_index))
    return signature


def _storage_looks_like_return(storage_repr: Optional[str]) -> bool:
    if not storage_repr:
        return False
    return any(reg in storage_repr for reg in ("RAX", "EAX", "AX"))


def _match_register_only_locals(
    source_locals: List[Dict],
    ghidra_locals: List[Dict],
) -> Tuple[List[Dict], List[Dict], List[Dict]]:
    new_matches: List[Dict] = []
    remaining_source: List[Dict] = []
    remaining_ghidra = list(ghidra_locals)
    register_candidates = [loc for loc in ghidra_locals if (loc.get("storage") or {}).get("is_register")]

    for src_var in source_locals:
        best = None
        best_score = None
        second_score = None
        src_calls = _call_signature(src_var.get("call_sites"))
        src_returned = bool(src_var.get("returned"))
        for candidate in register_candidates:
            cand_calls = _call_signature(candidate.get("call_sites"))
            score = 0
            use_delta = abs(len(candidate.get("use_addresses") or []) - len(src_var.get("uses") or []))
            score += use_delta
            score += len(src_calls - cand_calls) * 3
            score += len(cand_calls - src_calls) * 2
            if src_calls & cand_calls:
                score -= len(src_calls & cand_calls) * 2
            cand_returned = bool(candidate.get("is_returned"))
            storage_repr = (candidate.get("storage") or {}).get("repr")
            if src_returned:
                if cand_returned:
                    score -= 3
                elif _storage_looks_like_return(storage_repr):
                    score -= 2
                else:
                    score += 4
            else:
                if cand_returned:
                    score += 2
            if best is None or score < best_score:
                second_score = best_score
                best = candidate
                best_score = score
            elif second_score is None or score < second_score:
                second_score = score
        if best is None:
            remaining_source.append(src_var)
            continue
        if second_score is None or best_score + 2 <= second_score:
            if best_score <= 5:
                assignment = {
                    "ghidra_name": best.get("name"),
                    "ghidra_type": best.get("data_type"),
                    "suggested_name": src_var.get("name"),
                    "storage": best.get("storage"),
                    "use_addresses": best.get("use_addresses"),
                }
                new_matches.append(
                    {
                        "source": src_var,
                        "assigned": [assignment],
                        "notes": [],
                    }
                )
                register_candidates.remove(best)
                remaining_ghidra.remove(best)
            else:
                remaining_source.append(src_var)
        else:
            remaining_source.append(src_var)

    return new_matches, remaining_source, remaining_ghidra


def _run_ghidra_dump(
    functions: Sequence[str],
    ghidra_home: str,
    project_dir: str,
    project_name: str,
    binary_name: str,
) -> str:
    analyze_headless = os.path.join(ghidra_home, "support", "analyzeHeadless")
    if not os.path.exists(analyze_headless):
        raise SystemExit("analyzeHeadless not found at {}".format(analyze_headless))

    os.makedirs(REPORT_DIR, exist_ok=True)

    cmd = [
        analyze_headless,
        project_dir,
        project_name,
        "-readOnly",
        "-process",
        binary_name,
        "-scriptPath",
        os.path.join(REPO_ROOT, "ghidra_scripts"),
        "-postScript",
        "DumpFunctionLocals.py",
        "functions={}".format(",".join(functions)),
        "output={}".format(GHIDRA_OUTPUT_JSON),
    ]

    env = os.environ.copy()
    proc = subprocess.run(
        cmd,
        cwd=REPO_ROOT,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    if proc.returncode != 0:
        sys.stderr.write(proc.stdout)
        sys.stderr.write(proc.stderr)
        raise SystemExit("Ghidra headless execution failed with code {}".format(proc.returncode))
    if proc.stdout:
        sys.stdout.write(proc.stdout)
    if proc.stderr:
        sys.stderr.write(proc.stderr)
    return GHIDRA_OUTPUT_JSON


def _load_ghidra_locals(path: str) -> Dict[str, Dict]:
    with open(path, "r", encoding="utf-8") as infile:
        data = json.load(infile)
    output = {}
    for entry in data.get("functions", []):
        output[entry["name"]] = entry
    return output


def _match_locals(
    functions: Sequence[str],
    source_metadata: Dict[str, Dict],
    ghidra_metadata: Dict[str, Dict],
) -> List[Dict]:
    results: List[Dict] = []

    for func in functions:
        src_entry = source_metadata.get(func)
        gh_entry = ghidra_metadata.get(func)
        if not src_entry or not gh_entry:
            results.append(
                {
                    "function": func,
                    "source_locals": src_entry.get("locals") if src_entry else [],
                    "ghidra_locals": gh_entry.get("locals") if gh_entry else [],
                    "matches": [],
                    "unmatched_source": src_entry.get("locals") if src_entry else [],
                    "unmatched_ghidra": gh_entry.get("locals") if gh_entry else [],
                    "notes": ["Missing metadata for source or Ghidra function."],
                }
            )
            continue

        source_locals = src_entry["locals"]
        ghidra_locals = gh_entry.get("locals", [])
        ghidra_remaining = []
        for loc in ghidra_locals:
            loc["normalized_type"] = _normalize_type(loc.get("data_type"))
            ghidra_remaining.append(loc)

        match_list: List[Dict] = []
        unmatched_source = []
        used_names: set = set()

        for src_var in source_locals:
            normalized = _normalize_type(src_var.get("type"))
            src_var["normalized_type"] = normalized
            src_size_hint = _size_hint_from_normalized(normalized)
            src_var["size_hint"] = src_size_hint
            src_calls = _call_signature(src_var.get("call_sites"))
            src_returned = bool(src_var.get("returned"))
            def _score(candidate):
                score = 0
                storage = candidate.get("storage") or {}
                if storage.get("is_stack"):
                    score -= 2
                if storage.get("is_register"):
                    score += 1
                usage_delta = abs(len(candidate.get("use_addresses") or []) - len(src_var.get("uses") or []))
                score += usage_delta
                cand_calls = _call_signature(candidate.get("call_sites"))
                if src_calls:
                    matches = len(src_calls & cand_calls)
                    mismatches = len(src_calls - cand_calls)
                    score += mismatches * 3
                    score -= matches * 3
                candidate_returned = bool(candidate.get("is_returned"))
                if src_returned:
                    if candidate_returned:
                        score -= 2
                    else:
                        score += 4
                else:
                    if candidate_returned:
                        score += 2
                return score
            candidates = []
            fallback_options = []
            for loc in ghidra_remaining:
                if loc["normalized_type"] == normalized and normalized:
                    candidates.append(loc)
                else:
                    penalty = 3
                    loc_type = loc.get("normalized_type", "")
                    if _pointer_depth(normalized) != _pointer_depth(loc_type):
                        penalty += 3
                    base_close = _types_close(normalized, loc_type)
                    if base_close:
                        penalty = max(0, penalty - 1)
                    else:
                        penalty += 4
                    # Penalize large type-size mismatches for stack storage.
                    loc_size = loc.get("data_size")
                    if isinstance(src_size_hint, int) and isinstance(loc_size, int) and src_size_hint > 0 and loc_size > 0:
                        diff = abs(src_size_hint - loc_size)
                        min_size = min(src_size_hint, loc_size)
                        if diff >= max(4, min_size * 2):
                            penalty += 8
                    fallback_options.append((penalty, loc))

            chosen = None
            notes: List[str] = []

            if candidates:
                candidates.sort(key=_score)
                chosen = candidates[0]
            else:
                if fallback_options:
                    fallback_options.sort(key=lambda item: (_score(item[1]) + item[0], item[0]))
                    best_penalty, candidate = fallback_options[0]
                    storage = candidate.get("storage") or {}
                    if not storage.get("is_register"):
                        total_score = _score(candidate) + best_penalty
                        if total_score <= 5:
                            chosen = candidate
                            notes.append(
                                "Fallback match by storage/usage despite type mismatch ({} vs {}).".format(
                                    normalized or "unknown", candidate.get("normalized_type") or "unknown"
                                )
                            )

            if chosen is None:
                unmatched_source.append(src_var)
                continue

            ghidra_remaining.remove(chosen)

            suggested_name = _allocate_name(src_var["name"], used_names)
            match_entry = {
                "source": src_var,
                "assigned": [
                    {
                        "ghidra_name": chosen["name"],
                        "ghidra_type": chosen.get("data_type"),
                        "suggested_name": suggested_name,
                        "storage": chosen.get("storage"),
                        "use_addresses": chosen.get("use_addresses"),
                    }
                ],
                "notes": notes,
            }
            match_list.append(match_entry)

        # Handle leftover locals that share the same type as a matched variable.
        still_unmatched = []
        for candidate in ghidra_remaining:
            matched = False
            for match in match_list:
                src_type = match["source"].get("normalized_type")
                if src_type and src_type == candidate.get("normalized_type"):
                    base_name = match["source"]["name"]
                    suggested = _allocate_name(base_name, used_names)
                    match["assigned"].append(
                        {
                            "ghidra_name": candidate["name"],
                            "ghidra_type": candidate.get("data_type"),
                            "suggested_name": suggested,
                            "storage": candidate.get("storage"),
                            "use_addresses": candidate.get("use_addresses"),
                        }
                    )
                    matched = True
                    break
            if not matched:
                still_unmatched.append(candidate)

        if unmatched_source and still_unmatched:
            register_matches, unmatched_source, still_unmatched = _match_register_only_locals(
                unmatched_source,
                still_unmatched,
            )
            for match in register_matches:
                for assignment in match.get("assigned", []):
                    assignment["suggested_name"] = _allocate_name(assignment["suggested_name"], used_names)
            match_list.extend(register_matches)

        function_result = {
            "function": func,
            "source_file": src_entry["source"],
            "matches": match_list,
            "unmatched_source": unmatched_source,
            "unmatched_ghidra": still_unmatched,
            "ghidra_locals": ghidra_locals,
        }
        results.append(function_result)
    return results


def _write_report(results: List[Dict]) -> None:
    os.makedirs(REPORT_DIR, exist_ok=True)
    with open(MAPPING_REPORT_JSON, "w", encoding="utf-8") as outfile:
        json.dump({"results": results}, outfile, indent=2)
        outfile.write("\n")


def _print_summary(results: List[Dict]) -> None:
    print("\nVariable mapping summary:\n")
    for entry in results:
        print("Function: {}".format(entry["function"]))
        for match in entry["matches"]:
            src = match["source"]
            assigned = match["assigned"]
            assigned_names = ", ".join(
                "{}->{}".format(item["ghidra_name"], item["suggested_name"]) for item in assigned
            )
            print("  {} ({}) => {}".format(src["name"], src["type"], assigned_names))
            if match.get("notes"):
                for note in match["notes"]:
                    print("    note: {}".format(note))
        if entry["unmatched_source"]:
            print("  Unmatched source locals: {}".format(
                ", ".join(var["name"] for var in entry["unmatched_source"])
            ))
        if entry["unmatched_ghidra"]:
            print("  Unmatched ghidra locals: {}".format(
                ", ".join(var["name"] for var in entry["unmatched_ghidra"])
            ))
        print()


def parse_args(argv: Sequence[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--functions",
        nargs="+",
        help="Functions to analyze (defaults to the first five from xzre_locals.json).",
    )
    parser.add_argument(
        "--limit",
        type=int,
        default=5,
        help="Maximum number of functions to process when --functions is not provided (default: 5).",
    )
    parser.add_argument(
        "--ghidra-home",
        default=os.environ.get("GHIDRA_HOME", os.path.expanduser("~/tools/ghidra_11.4.2_PUBLIC")),
        help="Path to the Ghidra installation (defaults to GHIDRA_HOME or ~/tools/ghidra_11.4.2_PUBLIC).",
    )
    parser.add_argument(
        "--project-dir",
        default=DEFAULT_PROJECT_DIR,
        help="Directory containing the Ghidra project.",
    )
    parser.add_argument(
        "--project-name",
        default=DEFAULT_PROJECT_NAME,
        help="Name of the Ghidra project (default: xzre_ghidra).",
    )
    parser.add_argument(
        "--binary",
        default=DEFAULT_BINARY,
        help="Program name within the project to process (default: liblzma_la-crc64-fast.o).",
    )
    return parser.parse_args(argv)


def main(argv: Sequence[str]) -> None:
    args = parse_args(argv)
    mapping = _load_xzre_locals()
    functions = _get_functions_from_args(mapping, args.functions, args.limit)

    source_metadata = _collect_source_metadata(functions, mapping)
    ghidra_json_path = _run_ghidra_dump(
        functions,
        args.ghidra_home,
        args.project_dir,
        args.project_name,
        args.binary,
    )
    ghidra_metadata = _load_ghidra_locals(ghidra_json_path)
    results = _match_locals(functions, source_metadata, ghidra_metadata)
    _write_report(results)
    _print_summary(results)


if __name__ == "__main__":
    main(sys.argv[1:])
