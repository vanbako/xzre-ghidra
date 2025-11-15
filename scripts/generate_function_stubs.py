#!/usr/bin/env python3
"""
Generate per-function stub files that capture the current AutoDoc text, locals,
and provide space for fresh reverse-engineering notes.
"""

from __future__ import annotations

import argparse
import json
import textwrap
from collections import OrderedDict
from pathlib import Path
from typing import Dict, Iterable, List, Optional
import string


BATCHES: "OrderedDict[str, Dict[str, object]]" = OrderedDict(
    {
        "opco_patt": {
            "name": "Opcode Scanners & Pattern Utilities",
            "description": (
                "x86 disassembly helpers and search utilities that upstream "
                "analysis routines depend on."
            ),
            "functions": [
                "100020_x86_dasm",
                "100AC0_is_endbr64_instruction",
                "100B10_find_function_prologue",
                "100BA0_find_function",
                "100C90_find_call_instruction",
                "100D40_find_mov_lea_instruction",
                "100E00_find_mov_instruction",
                "100EB0_find_lea_instruction",
                "100F60_find_lea_instruction_with_mem_operand",
                "101020_find_string_reference",
                "101060_find_instruction_with_mem_operand_ex",
                "101120_find_instruction_with_mem_operand",
                "101170_find_add_instruction_with_mem_operand",
                "102C60_find_addr_referenced_in_mov_instruction",
                "102A50_elf_find_function_pointer",
                "102D30_elf_find_string_references",
                "1032C0_elf_find_string_reference",
                "10AC40_find_reg2reg_instruction",
            ],
        },
        "elf_mem": {
            "name": "ELF Introspection & Memory Utilities",
            "description": (
                "Segment walkers, relocation helpers, allocator shims, and "
                "other program-introspection building blocks."
            ),
            "functions": [
                "101210_fake_lzma_free",
                "101240_elf_contains_vaddr_impl",
                "1013A0_elf_contains_vaddr",
                "1013B0_is_gnu_relro",
                "1013D0_elf_parse",
                "101880_elf_symbol_get",
                "101B00_elf_symbol_get_addr",
                "101B30_c_memmove",
                "101B80_fake_lzma_alloc",
                "101B90_elf_find_rela_reloc",
                "101C30_elf_find_relr_reloc",
                "101DC0_elf_get_reloc_symbol",
                "101E60_elf_get_plt_symbol",
                "101E90_elf_get_got_symbol",
                "101EC0_elf_get_code_segment",
                "101F70_elf_get_rodata_segment",
                "1020A0_elf_find_string",
                "102150_elf_get_data_segment",
                "1022D0_elf_contains_vaddr_relro",
                "102370_is_range_mapped",
                "102440_j_tls_get_addr",
                "102490_get_lzma_allocator_address",
                "1024F0_get_elf_functions_address",
                "103CE0_main_elf_parse",
                "104030_init_elf_entry_ctx",
                "104060_get_lzma_allocator",
                "10D000_lzma_check_init",
                "10D008_tls_get_addr",
                "10D010_lzma_free",
                "10D018_lzma_alloc",
            ],
        },
        "sshd_recon": {
            "name": "SSHD Discovery & Sensitive Data Recon",
            "description": (
                "Hooks that identify sshd entry points, monitor structures, "
                "and sensitive-data flows."
            ),
            "functions": [
                "102550_sshd_find_main",
                "102FF0_sshd_find_monitor_field_addr_in_function",
                "103340_sshd_get_sensitive_data_address_via_krb5ccname",
                "103680_sshd_get_sensitive_data_address_via_xcalloc",
                "103870_sshd_get_sensitive_data_score_in_do_child",
                "103910_sshd_get_sensitive_data_score_in_main",
                "103990_sshd_get_sensitive_data_score_in_demote_sensitive_data",
                "103D50_sshd_get_sensitive_data_score",
                "103DB0_sshd_find_monitor_struct",
                "105410_sshd_find_sensitive_data",
                "1039C0_check_argument",
                "103A20_process_is_sshd",
                "107400_sshd_log",
                "107BC0_sshd_get_usable_socket",
                "107C60_sshd_get_client_socket",
                "107D50_sshd_patch_variables",
                "107DE0_sshd_configure_log_hook",
                "107EA0_check_backdoor_state",
                "107F20_extract_payload_message",
                "108270_sshd_proxy_elevate",
                "108080_mm_answer_keyverify_hook",
                "108100_mm_answer_authpassword_hook",
                "108EA0_mm_answer_keyallowed_hook",
                "10A3A0_mm_log_handler_hook",
                "108D50_decrypt_payload_message",
            ],
        },
        "loader_rt": {
            "name": "Loader Hooks & Runtime Setup",
            "description": (
                "Initialization of ld.so state, resolver hooks, GOT fixups, "
                "and backdoor staging."
            ),
            "functions": [
                "102770_init_ldso_ctx",
                "1027D0_init_hooks_ctx",
                "102850_init_shared_globals",
                "102890_init_imported_funcs",
                "102B10_validate_log_handler_pointers",
                "103F60_update_cpuid_got_index",
                "103F80_get_tls_get_addr_random_symbol_got_offset",
                "103FA0_update_got_address",
                "104010_update_got_offset",
                "104080_find_link_map_l_name",
                "104370_find_dl_naudit",
                "1045E0_resolve_libc_imports",
                "104660_process_shared_libraries_map",
                "104A40_process_shared_libraries",
                "104AE0_find_link_map_l_audit_any_plt_bitmask",
                "104EE0_find_link_map_l_audit_any_plt",
                "1051E0_find_dl_audit_offsets",
                "105830_backdoor_setup",
                "106F30_backdoor_init_stage2",
                "107030_c_strlen",
                "107050_c_strnlen",
                "107080_fd_read",
                "1070F0_fd_write",
                "107170_contains_null_pointers",
                "1074B0_count_pointers",
                "10A700_cpuid_gcc",
                "10A720_backdoor_entry",
                "10A794_backdoor_init",
                "10A800_get_cpuid_modified",
                "xzre_globals",
            ],
        },
        "crypto_cmd": {
            "name": "Crypto, Secret Data & Command Channel",
            "description": (
                "Cryptographic helpers, sshbuf serializers, secret-data "
                "staging, and RSA/MM command hooks."
            ),
            "functions": [
                "103B80_dsa_key_hash",
                "107190_chacha_decrypt",
                "1072B0_sha256",
                "107320_bignum_serialize",
                "107510_rsa_key_hash",
                "107630_verify_signature",
                "107A20_sshd_get_sshbuf",
                "107920_sshbuf_bignum_is_negative",
                "107950_sshbuf_extract",
                "1081D0_secret_data_get_decrypted",
                "1094A0_run_backdoor_commands",
                "10A240_hook_RSA_public_decrypt",
                "10A2D0_hook_EVP_PKEY_set1_RSA",
                "10A330_hook_RSA_get0_key",
                "10A860_count_bits",
                "10A880_get_string_id",
                "10A990_secret_data_append_from_instruction",
                "10AA00_secret_data_append_from_code",
                "10AAC0_secret_data_append_singleton",
                "10AB70_secret_data_append_item",
                "10AB90_secret_data_append_from_address",
                "10ABC0_secret_data_append_from_call_site",
                "10ABE0_secret_data_append_items",
            ],
        },
    }
)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--metadata",
        type=Path,
        default=Path("metadata/functions_autodoc.json"),
        help="Path to functions_autodoc.json (default: %(default)s)",
    )
    parser.add_argument(
        "--locals",
        type=Path,
        default=Path("metadata/xzre_locals.json"),
        help="Path to xzre_locals.json (default: %(default)s)",
    )
    parser.add_argument(
        "--output-dir",
        type=Path,
        default=Path("notes"),
        help="Directory where stub files will be written (default: %(default)s)",
    )
    parser.add_argument(
        "--batch",
        action="append",
        choices=list(BATCHES.keys()),
        help="Generate stubs for one or more short batch names "
        "(can be repeated; default: all batches)",
    )
    parser.add_argument(
        "--function",
        dest="functions",
        action="append",
        help="Generate a stub for a specific function (can be repeated)",
    )
    parser.add_argument(
        "--force",
        action="store_true",
        help="Overwrite existing stub files",
    )
    return parser.parse_args()


def build_function_list(args: argparse.Namespace) -> List[str]:
    ordered: List[str] = []
    if args.batch:
        for batch_key in args.batch:
            ordered.extend(BATCHES[batch_key]["functions"])  # type: ignore[index]
    if not args.batch and not args.functions:
        for meta in BATCHES.values():
            ordered.extend(meta["functions"])  # type: ignore[index]
    if args.functions:
        ordered.extend(args.functions)

    seen = set()
    result: List[str] = []
    for name in ordered:
        if name in seen:
            continue
        seen.add(name)
        result.append(name)
    return result


def load_json(path: Path) -> Dict:
    if not path.exists():
        raise FileNotFoundError(path)
    with path.open("r", encoding="utf-8") as handle:
        return json.load(handle)


def format_autodoc(text: Optional[str]) -> str:
    if not text:
        return "_No entry in metadata/functions_autodoc.json._"
    sanitized = text.rstrip("\n")
    return "```text\n" + sanitized + "\n```\n"


def format_locals(entry: Optional[Dict]) -> str:
    if not entry or not entry.get("locals"):
        return "_No locals recorded in metadata/xzre_locals.json._"
    lines = ["| Name | Type |", "| --- | --- |"]
    for item in entry["locals"]:
        name = item.get("name", "")
        typ = item.get("type", "")
        lines.append(f"| {name} | {typ} |")
    return "\n".join(lines) + "\n"


def find_batch_for_function(name: str) -> Optional[str]:
    for key, meta in BATCHES.items():
        if name in meta["functions"]:  # type: ignore[index]
            return key
    return None


def render_stub(
    name: str,
    batch_key: Optional[str],
    autodoc_text: Optional[str],
    locals_entry: Optional[Dict],
) -> str:
    batch_line = "- Batch: (unassigned)"
    description_line = ""
    if batch_key:
        batch_meta = BATCHES[batch_key]
        batch_line = f"- Batch: {batch_meta['name']} (`{batch_key}`)"
        description_line = f"- Batch focus: {batch_meta['description']}"

    source_path = (
        locals_entry.get("source")
        if locals_entry and isinstance(locals_entry, dict)
        else None
    )
    source_line = (
        f"- Source: {source_path}"
        if source_path
        else "- Source: (not recorded)"
    )

    autodoc_block = format_autodoc(autodoc_text)
    locals_block = format_locals(locals_entry)

    template = f"""# {name}

{batch_line}
{description_line}
{source_line}

## Current AutoDoc
{autodoc_block}
## Locals Snapshot
{locals_block}
## Notes
- Pending observations:

## Follow-ups
- [ ] Update metadata/functions_autodoc.json (use scripts/edit_autodoc.py)
- [ ] Adjust metadata/xzre_locals.json if local names/types change
"""
    return textwrap.dedent(template).strip() + "\n"


def ensure_output_dir(path: Path) -> None:
    path.mkdir(parents=True, exist_ok=True)


def write_stub(path: Path, content: str, force: bool) -> bool:
    if path.exists() and not force:
        return False
    path.write_text(content, encoding="utf-8")
    return True


def lookup_with_suffix(mapping: Dict, name: str):
    entry = mapping.get(name)
    if entry is not None:
        return entry
    prefix, sep, suffix = name.partition("_")
    if not sep:
        return None
    if len(prefix) < 5:
        return None
    if not all(ch in string.hexdigits for ch in prefix):
        return None
    return mapping.get(suffix)


def main() -> int:
    args = parse_args()
    functions = build_function_list(args)
    if not functions:
        print("No functions matched the selection.")
        return 1

    autodoc_data = load_json(args.metadata)
    locals_data = load_json(args.locals)

    ensure_output_dir(args.output_dir)

    wrote_any = False
    for func in functions:
        batch_key = find_batch_for_function(func)
        autodoc_text = lookup_with_suffix(autodoc_data, func)
        locals_entry = lookup_with_suffix(locals_data, func)
        stub_text = render_stub(func, batch_key, autodoc_text, locals_entry)
        sanitized_name = func.replace("/", "_")
        output_path = args.output_dir / f"{sanitized_name}.md"
        if write_stub(output_path, stub_text, args.force):
            wrote_any = True
            print(f"[wrote] {output_path}")
        else:
            print(f"[skip] {output_path} already exists (use --force to override)")

    if not wrote_any:
        print("No new stub files were created.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
