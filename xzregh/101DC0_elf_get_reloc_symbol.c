// /home/kali/xzre-ghidra/xzregh/101DC0_elf_get_reloc_symbol.c
// Function: elf_get_reloc_symbol @ 0x101DC0
// Calling convention: unknown
// Prototype: undefined elf_get_reloc_symbol(void)


/*
 * AutoDoc: Generic helper that scans an arbitrary relocation array for undefined symbols of a specific relocation type (e.g., GOT vs PLT) and a specific encoded name. It iterates through `num_relocs`, ensures the relocation type matches `reloc_type`, confirms the associated symbol is really an import (`st_shndx == 0`), and then resolves the symbol name via `get_string_id` before comparing it to `encoded_string_id`. When it finds a match it returns the relocated address (`elfbase + r_offset`) so the caller can patch GOT/PLT entries in place.
 */
#include "xzre_types.h"


long elf_get_reloc_symbol(long *param_1,long *param_2,uint param_3,ulong param_4,int param_5)

{
  int iVar1;
  uint *puVar2;
  ulong uVar3;
  
  iVar1 = secret_data_append_from_address(0,0x67,5,4);
  uVar3 = 0;
  if (iVar1 != 0) {
    for (; uVar3 < param_3; uVar3 = uVar3 + 1) {
      if ((((param_2[1] & 0xffffffffU) == param_4) &&
          (puVar2 = (uint *)(((ulong)param_2[1] >> 0x20) * 0x18 + param_1[7]),
          *(short *)((long)puVar2 + 6) == 0)) &&
         (iVar1 = get_string_id((ulong)*puVar2 + param_1[6],0), iVar1 == param_5)) {
        return *param_2 + *param_1;
      }
      param_2 = param_2 + 3;
    }
  }
  return 0;
}

