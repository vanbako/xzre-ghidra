# Lists available calling conventions for the current program.
# @category xzre


def main():
    comp_spec = currentProgram.getCompilerSpec()
    lang = currentProgram.getLanguage()
    print("language={}".format(lang.getLanguageID()))
    print("compilerSpec={}".format(comp_spec.getCompilerSpecID()))
    conventions = comp_spec.getCallingConventions()
    names = sorted(c.getName() for c in conventions)
    for name in names:
        print(name)
    default_cc = comp_spec.getDefaultCallingConvention()
    default_name = default_cc.getName() if default_cc else None
    print("default={}".format(default_name))


if __name__ == "__main__":
    main()
