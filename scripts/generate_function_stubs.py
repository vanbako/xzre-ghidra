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
                "100020_x86_decode_instruction",
                "100AC0_is_endbr32_or_64",
                "100B10_find_endbr_prologue",
                "100BA0_find_function_bounds",
                "100C90_find_rel32_call_instruction",
                "100D40_find_riprel_mov_or_lea",
                "100E00_find_riprel_mov",
                "100EB0_find_lea_with_displacement",
                "100F60_find_riprel_lea",
                "101020_find_string_lea_xref",
                "101060_find_riprel_opcode_memref_ex",
                "101120_find_riprel_ptr_lea_or_mov_load",
                "101170_find_riprel_grp1_imm8_memref",
                "102C60_find_riprel_mov_load_target_in_range",
                "102A50_elf_find_function_ptr_slot",
                "102D30_elf_build_string_xref_table",
                "1032C0_elf_find_encoded_string_xref_site",
                "10AC40_find_reg_to_reg_instruction",
            ],
        },
        "elf_mem": {
            "name": "ELF Introspection & Memory Utilities",
            "description": (
                "Segment walkers, relocation helpers, allocator shims, and "
                "other program-introspection building blocks."
            ),
            "functions": [
                "101210_fake_lzma_free_noop",
                "101240_elf_vaddr_range_has_pflags_impl",
                "1013A0_elf_vaddr_range_has_pflags",
                "1013B0_is_pt_gnu_relro",
                "1013D0_elf_info_parse",
                "101880_elf_gnu_hash_lookup_symbol",
                "101B00_elf_gnu_hash_lookup_symbol_addr",
                "101B30_memmove_overlap_safe",
                "101B80_fake_lzma_alloc_resolve_symbol",
                "101B90_elf_rela_find_relative_slot",
                "101C30_elf_relr_find_relative_slot",
                "101DC0_elf_find_import_reloc_slot",
                "101E60_elf_find_plt_reloc_slot",
                "101E90_elf_find_got_reloc_slot",
                "101EC0_elf_get_text_segment",
                "101F70_elf_get_rodata_segment_after_text",
                "1020A0_elf_find_encoded_string_in_rodata",
                "102150_elf_get_writable_tail_span",
                "1022D0_elf_vaddr_range_in_relro_if_required",
                "102370_is_range_mapped_via_pselect",
                "102440_tls_get_addr_trampoline",
                "102490_get_fake_lzma_allocator_blob",
                "1024F0_get_elf_functions_table",
                "103CE0_main_elf_resolve_stack_end_if_sshd",
                "104030_init_cpuid_ifunc_entry_ctx",
                "104060_get_fake_lzma_allocator",
            ],
        },
        "sshd_recon": {
            "name": "SSHD Discovery & Sensitive Data Recon",
            "description": (
                "Hooks that identify sshd entry points, monitor structures, "
                "and sensitive-data flows."
            ),
            "functions": [
                "102550_sshd_find_main_from_entry_stub",
                "102FF0_sshd_find_monitor_field_slot_via_mm_request_send",
                "103340_sshd_find_sensitive_data_base_via_krb5ccname",
                "103680_sshd_find_sensitive_data_base_via_xcalloc",
                "103870_sshd_score_sensitive_data_candidate_in_do_child",
                "103910_sshd_score_sensitive_data_candidate_in_main",
                "103990_sshd_score_sensitive_data_candidate_in_demote_sensitive_data",
                "103D50_sshd_score_sensitive_data_candidate",
                "103DB0_sshd_find_monitor_ptr_slot",
                "105410_sshd_recon_bootstrap_sensitive_data",
                "1039C0_argv_dash_option_contains_lowercase_d",
                "103A20_sshd_validate_stack_argv_envp_layout",
                "107400_sshd_log_via_sshlogv",
                "107BC0_sshd_find_socket_fd_by_shutdown_probe",
                "107C60_sshd_get_monitor_comm_fd",
                "107D50_sshd_patch_permitrootlogin_usepam_and_hook_authpassword",
                "107DE0_sshd_install_mm_log_handler_hook",
                "107EA0_payload_stream_validate_or_poison",
                "107F20_sshbuf_extract_rsa_modulus",
                "108270_sshd_monitor_cmd_dispatch",
                "108080_mm_answer_keyverify_send_staged_reply_hook",
                "108100_mm_answer_authpassword_send_reply_hook",
                "108EA0_mm_answer_keyallowed_payload_dispatch_hook",
                "10A3A0_mm_log_handler_hide_auth_success_hook",
                "108D50_payload_stream_decrypt_and_append_chunk",
            ],
        },
        "loader_rt": {
            "name": "Loader Hooks & Runtime Setup",
            "description": (
                "Initialization of ld.so state, resolver hooks, GOT fixups, "
                "and backdoor staging."
            ),
            "functions": [
                "102770_restore_ldso_audit_state",
                "1027D0_hooks_ctx_init_or_wait_for_shared_globals",
                "102850_init_backdoor_shared_globals",
                "102890_libcrypto_imports_ready_or_install_bootstrap",
                "102B10_sshd_validate_log_handler_slots",
                "103F60_cache_cpuid_gotplt_slot_index",
                "103F80_seed_got_ctx_for_tls_get_addr_parse",
                "103FA0_resolve_gotplt_base_from_tls_get_addr",
                "104010_cache_got_base_offset_from_cpuid_anchor",
                "104080_find_link_map_l_name_offsets",
                "104370_find_dl_naudit_slot",
                "1045E0_resolve_libc_read_errno_imports",
                "104660_scan_link_map_and_init_shared_libs",
                "104A40_scan_shared_libraries_via_r_debug",
                "104AE0_find_l_audit_any_plt_mask_and_slot",
                "104EE0_find_l_audit_any_plt_mask_via_symbind_alt",
                "1051E0_resolve_ldso_audit_offsets",
                "105830_backdoor_install_runtime_hooks",
                "106F30_cpuid_ifunc_stage2_install_hooks",
                "107030_strlen_unbounded",
                "107050_strnlen_bounded",
                "107080_fd_read_full",
                "1070F0_fd_write_full",
                "107170_pointer_array_has_null",
                "1074B0_count_null_terminated_ptrs",
                "10A700_cpuid_gcc",
                "10A720_cpuid_ifunc_resolver_entry",
                "10A794_cpuid_ifunc_patch_got_for_stage2",
                "10A800_get_cpuid_modified",
                "backdoor_hooks_data_blob",
            ],
        },
        "crypto_cmd": {
            "name": "Crypto, Secret Data & Command Channel",
            "description": (
                "Cryptographic helpers, sshbuf serializers, secret-data "
                "staging, and RSA/MM command hooks."
            ),
            "functions": [
                "103B80_dsa_pubkey_sha256_fingerprint",
                "107190_chacha20_decrypt",
                "1072B0_sha256_digest",
                "107320_bignum_mpint_serialize",
                "107510_rsa_pubkey_sha256_fingerprint",
                "107630_verify_ed448_signed_payload",
                "107A20_sshd_find_forged_modulus_sshbuf",
                "107920_sshbuf_is_negative_mpint",
                "107950_sshbuf_extract_ptr_and_len",
                "1081D0_secret_data_decrypt_with_embedded_seed",
                "1094A0_rsa_backdoor_command_dispatch",
                "10A240_rsa_public_decrypt_backdoor_shim",
                "10A2D0_evp_pkey_set1_rsa_backdoor_shim",
                "10A330_rsa_get0_key_backdoor_shim",
                "10A860_popcount_u64",
                "10A880_encoded_string_id_lookup",
                "10A990_secret_data_append_opcode_bit",
                "10AA00_secret_data_append_code_bits",
                "10AAC0_secret_data_append_singleton_bits",
                "10AB70_secret_data_append_item_if_enabled",
                "10AB90_secret_data_append_bits_from_addr_or_ret",
                "10ABC0_secret_data_append_bits_from_call_site",
                "10ABE0_secret_data_append_items_batch",
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
