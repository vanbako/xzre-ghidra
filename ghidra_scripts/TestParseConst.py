# @category xzre
from ghidra.app.util.cparser.C import CParser

def main():
    parser = CParser(currentProgram.getDataTypeManager())
    src = "typedef int BOOL;\nextern BOOL test_func(const char *str);"
    dt = parser.parse(src)
    print(dt.getName(), dt.__class__.__name__)
    print("proto:", dt.getPrototypeString(True))

if __name__ == "__main__":
    main()
