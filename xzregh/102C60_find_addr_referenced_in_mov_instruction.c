// /home/kali/xzre-ghidra/xzregh/102C60_find_addr_referenced_in_mov_instruction.c
// Function: find_addr_referenced_in_mov_instruction @ 0x102C60
// Calling convention: __stdcall
// Prototype: void * __stdcall find_addr_referenced_in_mov_instruction(StringXrefId id, string_references_t * refs, void * mem_range_start, void * mem_range_end)


/*
 * AutoDoc: Given a `StringXrefId`, this helper looks up the owning function span and walks it for MOV-load references.
 * It repeatedly calls `find_instruction_with_mem_operand_ex` (opcode 0x10b), ignores 64-bit/REX.W MOVs, and either recomputes the absolute address (handling RIP-relative displacements) or bails out if the candidate lacked DF2 and the caller never supplied a range.
 * The first pointer that lands inside `[mem_range_start, mem_range_end)` is returned; everything else yields NULL.
 */

#include "xzre_types.h"

void * find_addr_referenced_in_mov_instruction
                 (StringXrefId id,string_references_t *refs,void *mem_range_start,
                 void *mem_range_end)

{
  u8 *func_end;
  BOOL mov_found;
  u8 *candidate_addr;
  long ctx_clear_idx;
  dasm_ctx_t *ctx_clear_cursor;
  u8 *func_cursor;
  dasm_ctx_t scratch_ctx;
  
  ctx_clear_cursor = &scratch_ctx;
  // AutoDoc: Reset the scratch decoder we hand to `find_instruction_with_mem_operand_ex`.
  for (ctx_clear_idx = 0x16; ctx_clear_idx != 0; ctx_clear_idx = ctx_clear_idx + -1) {
    *(undefined4 *)&ctx_clear_cursor->instruction = 0;
    ctx_clear_cursor = (dasm_ctx_t *)((long)&ctx_clear_cursor->instruction + 4);
  }
  // AutoDoc: Fetch the cached `[func_start, func_end)` range associated with this string ID.
  func_cursor = (u8 *)(&refs->xcalloc_zero_size)[id].func_start;
  if (func_cursor != (u8 *)0x0) {
    func_end = (u8 *)(&refs->xcalloc_zero_size)[id].func_end;
    while (func_cursor < func_end) {
      mov_found = find_instruction_with_mem_operand_ex(func_cursor,func_end,&scratch_ctx,0x10b,(void *)0x0);
      if (mov_found == FALSE) {
        func_cursor = func_cursor + 1;
      }
      else {
        if (((byte)scratch_ctx.prefix.decoded.rex & 0x48) != 0x48) {
        // AutoDoc: Ignore MOVs that flip REX.W; the string tables we track always use 32-bit pointers.
          if ((scratch_ctx.prefix.decoded.flags2 & 1) == 0) {
          // AutoDoc: Without DF2 there is no displacement to recompute, so abort unless the caller insisted on a range.
            if (mem_range_start == (void *)0x0) {
              return (u8 *)0x0;
            }
          }
          else {
            candidate_addr = (u8 *)scratch_ctx.mem_disp;
            if (((uint)scratch_ctx.prefix.decoded.modrm & 0xff00ff00) == 0x5000000) {
            // AutoDoc: RIP-relative ModRM forms need the extra `instruction + instruction_size` correction.
              candidate_addr = (u8 *)(scratch_ctx.mem_disp + (long)scratch_ctx.instruction) +
                       scratch_ctx.instruction_size;
            }
            if ((mem_range_start <= candidate_addr) && (candidate_addr <= (u8 *)((long)mem_range_end + -4))) {
            // AutoDoc: Treat the range as inclusive of the start and exclusive of the four-byte tail so we only return pointers inside the blob.
              return candidate_addr;
            }
          }
        }
        func_cursor = func_cursor + scratch_ctx.instruction_size;
      }
    }
  }
  return (u8 *)0x0;
}

