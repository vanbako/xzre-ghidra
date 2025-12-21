// /home/kali/xzre-ghidra/xzregh/102C60_find_riprel_mov_load_target_in_range.c
// Function: find_riprel_mov_load_target_in_range @ 0x102C60
// Calling convention: __stdcall
// Prototype: void * __stdcall find_riprel_mov_load_target_in_range(StringXrefId id, string_references_t * refs, void * mem_range_start, void * mem_range_end)


/*
 * AutoDoc: Given a `StringXrefId`, this helper looks up the owning function span and walks it for MOV-load references.
 * It repeatedly calls `find_riprel_opcode_memref_ex` (opcode `X86_OPCODE_MOV_LOAD` / 0x10b), ignores 64-bit/REX.W MOVs, and recomputes the absolute address for RIP-relative disp32 operands (ModRM `mod=0`, `rm=5`) as `instruction + instruction_size + mem_disp`.
 * The first pointer that lands inside `[mem_range_start, mem_range_end)` is returned; everything else yields NULL.
 */

#include "xzre_types.h"

void * find_riprel_mov_load_target_in_range
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
  // AutoDoc: Reset the scratch decoder we hand to `find_riprel_opcode_memref_ex`.
  for (ctx_clear_idx = 0x16; ctx_clear_idx != 0; ctx_clear_idx = ctx_clear_idx + -1) {
    *(u32 *)&ctx_clear_cursor->instruction = 0;
    ctx_clear_cursor = (dasm_ctx_t *)((u8 *)ctx_clear_cursor + 4);
  }
  // AutoDoc: Fetch the cached `[func_start, func_end)` range associated with this string ID.
  func_cursor = (u8 *)(&refs->xcalloc_zero_size)[id].func_start;
  if (func_cursor != (u8 *)0x0) {
    func_end = (u8 *)(&refs->xcalloc_zero_size)[id].func_end;
    while (func_cursor < func_end) {
      mov_found = find_riprel_opcode_memref_ex
                        (func_cursor,func_end,&scratch_ctx,X86_OPCODE_1B_MOV_LOAD,(void *)0x0);
      if (mov_found == FALSE) {
        func_cursor = func_cursor + 1;
      }
      else {
        if ((scratch_ctx.prefix.modrm_bytes.rex_byte & 0x48) != 0x48) {
        // AutoDoc: Ignore MOVs that flip REX.W; the string tables we track always use 32-bit pointers.
          if ((scratch_ctx.prefix.decoded.flags2 & 1) == 0) {
          // AutoDoc: Without `DF2_MEM_DISP` there is no displacement to recompute, so abort unless the caller insisted on a range.
            if (mem_range_start == (void *)0x0) {
              return (u8 *)0x0;
            }
          }
          else {
            candidate_addr = (u8 *)scratch_ctx.mem_disp;
            if (((uint)scratch_ctx.prefix.decoded.modrm & XZ_MODRM_RIPREL_DISP32_MASK) == XZ_MODRM_RIPREL_DISP32) {
            // AutoDoc: RIP-relative disp32 (ModRM `mod=0`, `rm=5`) needs the extra `instruction + instruction_size` correction.
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

