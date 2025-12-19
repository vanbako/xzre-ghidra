# Prints the current signature strings for a few key xzre functions.
# @category xzre

from ghidra.program.model.data import Pointer, TypeDef


SAMPLE_FUNCTIONS = {
    "find_endbr_prologue",
    "rsa_backdoor_command_dispatch",
    "sshd_monitor_cmd_dispatch",
    "rsa_get0_key_backdoor_shim",
    "cpuid_ifunc_resolver_entry",
    "evp_pkey_set1_rsa_backdoor_shim",
    "elf_rela_find_relative_slot",
    "elf_relr_find_relative_slot",
    "tls_get_addr_trampoline",
    "elf_vaddr_range_has_pflags_impl",
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
