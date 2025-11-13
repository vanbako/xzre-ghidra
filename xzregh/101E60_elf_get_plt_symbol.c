// /home/kali/xzre-ghidra/xzregh/101E60_elf_get_plt_symbol.c
// Function: elf_get_plt_symbol @ 0x101E60
// Calling convention: unknown
// Prototype: undefined elf_get_plt_symbol(void)


/*
 * AutoDoc: Looks up the PLT thunk for a given symbol by delegating to `elf_get_reloc_symbol` with relocation type 7 (R_X86_64_JUMP_SLOT). It first makes sure the module actually advertised a PLT relocation table (flag bit 1) and caches its size, then returns the GOT/PLT entry that will be overwritten during hook installation. NULL means either the relocation table was absent or the requested symbol never appeared there.
 */
#include "xzre_types.h"


undefined8 elf_get_plt_symbol(long param_1,undefined4 param_2)

{
  undefined8 uVar1;
  
  if (((*(byte *)(param_1 + 0xd0) & 1) != 0) && (*(int *)(param_1 + 0x48) != 0)) {
    uVar1 = elf_get_reloc_symbol
                      (param_1,*(undefined8 *)(param_1 + 0x40),*(int *)(param_1 + 0x48),7,param_2);
    return uVar1;
  }
  return 0;
}

