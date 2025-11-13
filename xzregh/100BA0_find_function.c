// /home/kali/xzre-ghidra/xzregh/100BA0_find_function.c
// Function: find_function @ 0x100BA0
// Calling convention: unknown
// Prototype: undefined find_function(void)


/*
 * AutoDoc: Combines the prologue scan with a forward sweep to determine both the start and end addresses of a function. Backdoor initialization relies on it when it needs exact bounds for copying original bytes or scheduling follow-up pattern searches.
 */
#include "xzre_types.h"


undefined8
find_function(ulong param_1,ulong *param_2,ulong *param_3,ulong param_4,ulong param_5,
             undefined4 param_6)

{
  int iVar1;
  ulong uVar2;
  ulong search_from [2];
  
  search_from[0] = 0;
  uVar2 = param_1;
  if (param_2 != (ulong *)0x0) {
    while ((param_4 < uVar2 &&
           (iVar1 = find_function_prologue(uVar2,param_5,search_from,param_6), iVar1 == 0))) {
      uVar2 = uVar2 - 1;
    }
    uVar2 = search_from[0];
    if ((search_from[0] == 0) ||
       ((search_from[0] == param_4 &&
        (iVar1 = find_function_prologue(param_4,param_5,0,param_6), iVar1 == 0)))) {
      return 0;
    }
    *param_2 = uVar2;
  }
  param_1 = param_1 + 1;
  if (param_3 != (ulong *)0x0) {
    for (; param_1 < param_5 - 4; param_1 = param_1 + 1) {
      iVar1 = find_function_prologue(param_1,param_5,0,param_6);
      if (iVar1 != 0) goto LAB_00100c78;
    }
    if ((param_5 - 4 != param_1) ||
       (iVar1 = find_function_prologue(param_1,param_5,0,param_6), iVar1 != 0)) {
LAB_00100c78:
      param_5 = param_1;
    }
    *param_3 = param_5;
  }
  return 1;
}

