// /home/kali/xzre-ghidra/xzregh/102C60_find_addr_referenced_in_mov_instruction.c
// Function: find_addr_referenced_in_mov_instruction @ 0x102C60
// Calling convention: __stdcall
// Prototype: void * __stdcall find_addr_referenced_in_mov_instruction(StringXrefId id, string_references_t * refs, void * mem_range_start, void * mem_range_end)


/*
 * AutoDoc: Takes a string-reference entry and hunts through the owning function for MOV loads that reference a caller-supplied data range.
 * It repeatedly invokes `find_instruction_with_mem_operand_ex` for opcode `0x10b`, skips instructions that use the 64-bit register-only form, and recomputes RIP-relative addresses by adding `mem_disp` to the current instruction pointer when the ModRM demands it.
 * The first computed address that falls within `[mem_range_start, mem_range_end)` is returned, giving the loader the exact struct field a particular status string touches.
 */

#include "xzre_types.h"

void * find_addr_referenced_in_mov_instruction
                 (StringXrefId id,string_references_t *refs,void *mem_range_start,
                 void *mem_range_end)

{
  u8 *code_end;
  BOOL BVar1;
  u8 *puVar2;
  long lVar3;
  dasm_ctx_t *pdVar4;
  u8 *code_start;
  dasm_ctx_t scratch_ctx;
  
  pdVar4 = &scratch_ctx;
  for (lVar3 = 0x16; lVar3 != 0; lVar3 = lVar3 + -1) {
    *(undefined4 *)&pdVar4->instruction = 0;
    pdVar4 = (dasm_ctx_t *)((long)&pdVar4->instruction + 4);
  }
  code_start = (u8 *)refs->entries[id].func_start;
  if (code_start != (u8 *)0x0) {
    code_end = (u8 *)refs->entries[id].func_end;
    while (code_start < code_end) {
      BVar1 = find_instruction_with_mem_operand_ex(code_start,code_end,&scratch_ctx,0x10b,(void *)0x0);
      if (BVar1 == FALSE) {
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
            puVar2 = (u8 *)scratch_ctx.mem_disp;
            if (((uint)scratch_ctx.prefix.decoded.modrm & 0xff00ff00) == 0x5000000) {
              puVar2 = (u8 *)(scratch_ctx.mem_disp + (long)scratch_ctx.instruction) +
                       scratch_ctx.instruction_size;
            }
            if ((mem_range_start <= puVar2) && (puVar2 <= (u8 *)((long)mem_range_end + -4))) {
              return puVar2;
            }
          }
        }
        code_start = code_start + scratch_ctx.instruction_size;
      }
    }
  }
  return (u8 *)0x0;
}

