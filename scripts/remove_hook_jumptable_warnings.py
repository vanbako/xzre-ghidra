#!/usr/bin/env python3
"""
Replace noisy Ghidra jumptable warnings in hook functions with a clearer comment.
"""

from __future__ import annotations

import argparse
import pathlib
import re
import sys
from typing import Dict


HOOK_COMMENTS: Dict[str, str] = {
    "10A2D0_hook_EVP_PKEY_set1_RSA.c":
        "Hook tail-call: after run_backdoor_commands() it jumps through orig_EVP_PKEY_set1_RSA, "
        "so the saved pointer call only looks like a jumptable.",
    "10A240_hook_RSA_public_decrypt.c":
        "Hook tail-call: once the dispatcher forwards to OpenSSL it jumps via "
        "orig_RSA_public_decrypt, not through a jumptable.",
    "10A330_hook_RSA_get0_key.c":
        "Hook tail-call: after inspecting the RSA handle it calls orig_RSA_get0_key directly, "
        "so the tail jump is intentional.",
    "108EA0_mm_answer_keyallowed_hook.c":
        "Hook tail-call: after the payload state machine finishes it invokes "
        "orig_mm_answer_keyallowed through the saved pointer, so there is no jumptable.",
}

WARNING_BLOCK_RE = re.compile(
    r"\n(?P<indent>\s*)/\* WARNING: Could not recover jumptable at "
    r"0x[0-9a-fA-F]+\. Too many branches \*/\n"
    r"(?P=indent)/\* WARNING: Treating indirect jump as call \*/"
)


def patch_file(path: pathlib.Path, comment: str) -> bool:
    text = path.read_text()
    replacement = f"/* {comment} */"

    if replacement in text:
        return False

    def repl(match: re.Match[str]) -> str:
        indent = match.group("indent")
        return f"\n{indent}{replacement}"

    new_text, count = WARNING_BLOCK_RE.subn(repl, text, count=1)
    if count == 0:
        raise RuntimeError(f"could not find jumptable warning block in {path}")

    path.write_text(new_text)
    return True


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Replace Ghidra jumptable warnings in hook wrappers."
    )
    parser.add_argument(
        "--xzregh-dir",
        required=True,
        type=pathlib.Path,
        help="Directory containing exported xzregh/*.c files.",
    )
    args = parser.parse_args()
    changed = False

    for relative_path, comment in HOOK_COMMENTS.items():
        file_path = args.xzregh_dir / relative_path
        if not file_path.is_file():
            raise FileNotFoundError(f"missing hook source: {file_path}")
        if patch_file(file_path, comment):
            changed = True

    return 0 if not changed else 0


if __name__ == "__main__":
    sys.exit(main())
