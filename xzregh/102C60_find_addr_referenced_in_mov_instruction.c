// /home/kali/xzre-ghidra/xzregh/102C60_find_addr_referenced_in_mov_instruction.c
// Function: find_addr_referenced_in_mov_instruction @ 0x102C60
// Calling convention: __stdcall
// Prototype: void * __stdcall find_addr_referenced_in_mov_instruction(StringXrefId id, string_references_t * refs, void * mem_range_start, void * mem_range_end)


/*
 * AutoDoc: Walks the function owning a string reference, repeatedly calling `find_instruction_with_mem_operand_ex` for opcode `0x10b` to find MOV loads that touch data.
 * Skips register-only forms and 64-bit REX.W MOVs, recomputes the absolute address for displacement-based operands (RIP-relative when ModRM encodes it), and returns the first address that falls inside `[mem_range_start, mem_range_end)`.
 * Returns NULL when no qualifying reference is found or when register-only forms surface and no range was requested.
 */

#include "xzre_types.h"

void * find_addr_referenced_in_mov_instruction
                 (StringXrefId id,string_references_t *refs,void *mem_range_start,
                 void *mem_range_end)

{
  u8 *code_end;
  BOOL decode_ok;
  u8 *referenced_addr;
  long clear_idx;
  dasm_ctx_t *zero_ctx;
  u8 *code_start;
  dasm_ctx_t scratch_ctx;
  
  zero_ctx = &scratch_ctx;
  for (clear_idx = 0x16; clear_idx != 0; clear_idx = clear_idx + -1) {
    *(undefined4 *)&zero_ctx->instruction = 0;
    zero_ctx = (dasm_ctx_t *)((long)&zero_ctx->instruction + 4);
  }
  code_start = (u8 *)(&refs->xcalloc_zero_size)[id].func_start;
  if (code_start != (u8 *)0x0) {
    code_end = (u8 *)(&refs->xcalloc_zero_size)[id].func_end;
    while (code_start < code_end) {
      decode_ok = find_instruction_with_mem_operand_ex(code_start,code_end,&scratch_ctx,0x10b,(void *)0x0);
      if (decode_ok == FALSE) {
        code_start = code_start + 1;
      }
      else {
        if (((byte)scratch_ctx.prefix.decoded.rex & 0x48) != 0x48) {
          if ((scratch_ctx.prefix.decoded.flags2 & 1) == 0) {
            if (mem_range_start == (void *)0x0) {
              return (u8 *)0x0;
            }
          }
          else {
            referenced_addr = (u8 *)scratch_ctx.mem_disp;
            if (((uint)scratch_ctx.prefix.decoded.modrm & 0xff00ff00) == 0x5000000) {
              referenced_addr = (u8 *)(scratch_ctx.mem_disp + (long)scratch_ctx.instruction) +
                       scratch_ctx.instruction_size;
            }
            if ((mem_range_start <= referenced_addr) && (referenced_addr <= (u8 *)((long)mem_range_end + -4))) {
              return referenced_addr;
            }
          }
        }
        code_start = code_start + scratch_ctx.instruction_size;
      }
    }
  }
  return (u8 *)0x0;
}

