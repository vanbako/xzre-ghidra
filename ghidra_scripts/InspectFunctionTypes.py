# @category xzre

FUNCTIONS = [
    "find_string_reference",
    "dsa_key_hash",
    "resolve_libc_imports",
    "process_shared_libraries_map",
    "contains_null_pointers",
    "sha256",
    "bignum_serialize",
    "sshd_log",
    "rsa_key_hash",
    "verify_signature",
    "sshbuf_bignum_is_negative",
    "sshbuf_extract",
    "sshd_get_sshbuf",
    "sshd_get_client_socket",
    "extract_payload_message",
    "mm_answer_keyverify_hook",
    "mm_answer_authpassword_hook",
    "mm_answer_keyallowed_hook",
    "hook_RSA_public_decrypt",
    "hook_RSA_get0_key",
    "mm_log_handler_hook",
    "_cpuid_gcc",
    "backdoor_entry",
    "_get_cpuid_modified",
    "get_string_id",
    "secret_data_append_from_code",
    "secret_data_append_singleton",
    "secret_data_append_item",
    "secret_data_append_from_address",
    "secret_data_append_from_call_site",
    "secret_data_append_items",
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
