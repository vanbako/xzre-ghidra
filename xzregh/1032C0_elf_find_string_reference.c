// /home/kali/xzre-ghidra/xzregh/1032C0_elf_find_string_reference.c
// Function: elf_find_string_reference @ 0x1032C0
// Calling convention: unknown
// Prototype: undefined elf_find_string_reference(void)


/*
 * AutoDoc: Finds the first instruction that references a specific string literal between the supplied code bounds. The loader uses this pinpoint search to anchor subsequent pattern matching when triangulating hook targets from log messages and status strings.
 */
#include "xzre_types.h"


long elf_find_string_reference
               (undefined8 param_1,undefined4 param_2,undefined8 param_3,undefined8 param_4)

{
  int iVar1;
  long lVar2;
  long lVar3;
  undefined4 local_2c;
  
  local_2c = param_2;
  iVar1 = secret_data_append_from_call_site(0xd2,4,0xd,0);
  if (iVar1 != 0) {
    lVar2 = 0;
    while (lVar2 = elf_find_string(param_1,&local_2c,lVar2), lVar2 != 0) {
      lVar3 = find_string_reference(param_3,param_4,lVar2);
      if (lVar3 != 0) {
        return lVar3;
      }
      lVar2 = lVar2 + 1;
    }
  }
  return 0;
}

