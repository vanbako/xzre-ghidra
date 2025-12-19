# @category xzre

FUNCTIONS = [
    "find_string_lea_xref",
    "dsa_pubkey_sha256_fingerprint",
    "resolve_libc_read_errno_imports",
    "scan_link_map_and_init_shared_libs",
    "pointer_array_has_null",
    "sha256_digest",
    "bignum_mpint_serialize",
    "sshd_log_via_sshlogv",
    "rsa_pubkey_sha256_fingerprint",
    "verify_ed448_signed_payload",
    "sshbuf_is_negative_mpint",
    "sshbuf_extract_ptr_and_len",
    "sshd_find_forged_modulus_sshbuf",
    "sshd_get_monitor_comm_fd",
    "sshbuf_extract_rsa_modulus",
    "mm_answer_keyverify_send_staged_reply_hook",
    "mm_answer_authpassword_send_reply_hook",
    "mm_answer_keyallowed_payload_dispatch_hook",
    "rsa_public_decrypt_backdoor_shim",
    "rsa_get0_key_backdoor_shim",
    "mm_log_handler_hide_auth_success_hook",
    "cpuid_query_and_unpack",
    "cpuid_ifunc_resolver_entry",
    "get_cpuid_with_ifunc_bootstrap",
    "encoded_string_id_lookup",
    "secret_data_append_code_bits",
    "secret_data_append_singleton_bits",
    "secret_data_append_item_if_enabled",
    "secret_data_append_bits_from_addr_or_ret",
    "secret_data_append_bits_from_call_site",
    "secret_data_append_items_batch",
]

def describe(dt):
    qualifiers = []
    if hasattr(dt, "isConst") and dt.isConst():
        qualifiers.append("const")
    if hasattr(dt, "isVolatile") and dt.isVolatile():
        qualifiers.append("volatile")
    base = dt
    if hasattr(dt, "getDataType"):
        sub = dt.getDataType()
        if sub is not None:
            base = sub
    return "{}{} (name={}, class={})".format(
        " ".join(qualifiers) + " " if qualifiers else "",
        dt.getDisplayName(),
        dt.getName() if hasattr(dt, "getName") else "?",
        dt.__class__.__name__,
    )


def find_function_by_name(fm, target):
    for func in fm.getFunctions(True):
        if func.getName() == target:
            return func
    return None


def main():
    args = getScriptArgs()
    outfile = None
    for arg in args:
        if arg.startswith("output="):
            outfile = arg.split("=", 1)[1]
    out = None
    if outfile:
        out = open(outfile, "w")

    def emit(line):
        if out:
            out.write(line + "\n")
        else:
            print(line)

    fm = currentProgram.getFunctionManager()
    for name in FUNCTIONS:
        func = find_function_by_name(fm, name)
        if func is None:
            emit("{}: not found".format(name))
            continue
        sig = func.getSignature()
        emit("{} -> {}".format(name, sig.getPrototypeString(True)))
        params = sig.getArguments()
        for idx, param in enumerate(params):
            dt = param.getDataType()
            emit("  param{}: {}".format(idx, describe(dt)))
        emit("  return: {}".format(describe(sig.getReturnType())))
        emit("")

    if out:
        out.close()

if __name__ == "__main__":
    main()
