// /home/kali/xzre-ghidra/xzregh/103990_sshd_get_sensitive_data_score_in_demote_sensitive_data.c
// Function: sshd_get_sensitive_data_score_in_demote_sensitive_data @ 0x103990
// Calling convention: unknown
// Prototype: undefined sshd_get_sensitive_data_score_in_demote_sensitive_data(void)


/*
 * AutoDoc: Disassembles the `demote_sensitive_data` helper referenced in the string table and returns
 * three points if it ever references the candidate pointer. That routine is highly specific to
 * the real sensitive_data block, so even a single hit is treated as strong evidence.
 */
#include "xzre_types.h"


undefined1  [16]
sshd_get_sensitive_data_score_in_demote_sensitive_data
          (undefined8 param_1,undefined8 param_2,ulong param_3)

{
  undefined1 auVar1 [16];
  int iVar2;
  undefined8 uVar3;
  undefined1 auVar4 [16];
  
  if (*(long *)(param_3 + 0x68) != 0) {
    iVar2 = find_instruction_with_mem_operand
                      (*(long *)(param_3 + 0x68),*(undefined8 *)(param_3 + 0x70),0,param_1);
    if (iVar2 == 0) {
      uVar3 = 0;
    }
    else {
      uVar3 = 3;
    }
    auVar4._8_8_ = param_2;
    auVar4._0_8_ = uVar3;
    return auVar4;
  }
  auVar1._8_8_ = 0;
  auVar1._0_8_ = param_3;
  return auVar1 << 0x40;
}

