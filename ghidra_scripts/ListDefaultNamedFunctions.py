# Identifies functions that still use Ghidra auto-generated names so analysts can
# prioritize renaming and annotation passes.
# @category xzre

from ghidra.program.model.listing import CodeUnit


def has_default_name(name):
    default_prefixes = ("FUN_", "LAB_", "nullsub_", "sub_", "undefined")
    return name.startswith(default_prefixes)


def main():
    program = currentProgram
    listing = program.getListing()
    func_manager = program.getFunctionManager()

    total = 0
    for func in func_manager.getFunctions(True):
        name = func.getName()
        if not has_default_name(name):
            continue
        total += 1
        entry = func.getEntryPoint()
        signature = func.getSignature().getPrototypeString()
        plate_comment = listing.getComment(CodeUnit.PLATE_COMMENT, entry)
        has_plate = "yes" if plate_comment else "no"
        print(
            "{} {} plate_comment={} prototype={}".format(
                entry, name, has_plate, signature
            )
        )
    print("DEFAULT_FUNCTION_COUNT={}".format(total))


if __name__ == "__main__":
    main()
