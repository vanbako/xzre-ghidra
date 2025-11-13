// /home/kali/xzre-ghidra/xzregh/101B00_elf_symbol_get_addr.c
// Function: elf_symbol_get_addr @ 0x101B00
// Calling convention: unknown
// Prototype: undefined elf_symbol_get_addr(void)


/*
 * AutoDoc: Convenience layer on top of `elf_symbol_get`: look up the symbol, make sure it is defined (both `st_value` and `st_shndx` are non-zero), and then turn the symbol value into a process address by adding it to `elf_info->elfbase`. Returning NULL indicates either the symbol does not exist or it represents an import/resolver stub that lacks a concrete address.
 */
#include "xzre_types.h"


long elf_symbol_get_addr(long *param_1,undefined8 param_2)

{
  long lVar1;
  Elf64_Sym *sym;
  
  lVar1 = elf_symbol_get(param_1,param_2,0);
  if (lVar1 != 0) {
    if ((*(long *)(lVar1 + 8) == 0) || (*(short *)(lVar1 + 6) == 0)) {
      lVar1 = 0;
    }
    else {
      lVar1 = *param_1 + *(long *)(lVar1 + 8);
    }
  }
  return lVar1;
}

