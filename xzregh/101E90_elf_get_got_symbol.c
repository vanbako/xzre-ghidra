// /home/kali/xzre-ghidra/xzregh/101E90_elf_get_got_symbol.c
// Function: elf_get_got_symbol @ 0x101E90
// Calling convention: unknown
// Prototype: undefined elf_get_got_symbol(void)


/*
 * AutoDoc: Identical pattern but aimed at the main RELA table: it requires `flags & 2` (meaning RELA records were found) and then calls `elf_get_reloc_symbol` with relocation type 6 (R_X86_64_GLOB_DAT). Successful lookups hand back the writable GOT slot for the symbol so the loader can redirect it; failure means the symbol was not imported through a GOT relocation.
 */
#include "xzre_types.h"


undefined8 elf_get_got_symbol(long param_1,undefined4 param_2)

{
  undefined8 uVar1;
  
  if (((*(byte *)(param_1 + 0xd0) & 2) != 0) && (*(int *)(param_1 + 0x80) != 0)) {
    uVar1 = elf_get_reloc_symbol
                      (param_1,*(undefined8 *)(param_1 + 0x78),*(int *)(param_1 + 0x80),6,param_2);
    return uVar1;
  }
  return 0;
}

