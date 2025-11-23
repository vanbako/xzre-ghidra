# Prints the current signature strings for a few key xzre functions.
# @category xzre

from ghidra.program.model.data import Pointer, TypeDef


SAMPLE_FUNCTIONS = {
    "find_function_prologue",
    "run_backdoor_commands",
    "sshd_proxy_elevate",
    "hook_RSA_get0_key",
    "backdoor_entry",
    "hook_EVP_PKEY_set1_RSA",
    "elf_find_rela_reloc",
    "elf_find_relr_reloc",
    "j_tls_get_addr",
    "elf_contains_vaddr_impl",
}


def main():
    func_manager = currentProgram.getFunctionManager()
    found = {name: None for name in SAMPLE_FUNCTIONS}
    for func in func_manager.getFunctions(True):
        name = func.getName()
        if name in found:
            found[name] = func

    for name in sorted(SAMPLE_FUNCTIONS):
        func = found.get(name)
        if func is None:
            print("{}: <not found>".format(name))
            continue
        signature = func.getSignature().getPrototypeString(True)
        param_chunks = []
        for p in func.getParameters():
            dt = p.getDataType()
            chunk = "{} {}".format(dt.getName(), p.getName())
            if isinstance(dt, Pointer):
                base = dt.getDataType()
                if isinstance(base, TypeDef):
                    base_under = base.getDataType()
                else:
                    base_under = base
                if hasattr(base_under, "isImmutable") and base_under.isImmutable():
                    chunk += "[base const]"
            param_chunks.append(chunk)
        params = ", ".join(param_chunks)
        print(
            "{} @ {} -> {} | params=[{}]".format(
                name, func.getEntryPoint(), signature, params
            )
        )


if __name__ == "__main__":
    main()
