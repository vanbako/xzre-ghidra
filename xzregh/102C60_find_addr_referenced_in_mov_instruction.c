// /home/kali/xzre-ghidra/xzregh/102C60_find_addr_referenced_in_mov_instruction.c
// Function: find_addr_referenced_in_mov_instruction @ 0x102C60
// Calling convention: __stdcall
// Prototype: void * __stdcall find_addr_referenced_in_mov_instruction(StringXrefId id, string_references_t * refs, void * mem_range_start, void * mem_range_end)


/* WARNING: Type propagation algorithm not settling */

void * find_addr_referenced_in_mov_instruction
                 (StringXrefId id,string_references_t *refs,void *mem_range_start,
                 void *mem_range_end)

{
  u8 *code_end;
  BOOL BVar1;
  u8 *puVar2;
  long lVar3;
  u8 **ppuVar4;
  u8 *code_start;
  u8 *local_80;
  u64 local_78;
  undefined1 local_6f;
  undefined1 local_65;
  undefined4 local_64;
  u8 *local_50;
  
  ppuVar4 = &local_80;
  for (lVar3 = 0x16; lVar3 != 0; lVar3 = lVar3 + -1) {
    *(undefined4 *)ppuVar4 = 0;
    ppuVar4 = (u8 **)((long)ppuVar4 + 4);
  }
  code_start = (u8 *)refs->entries[id].func_start;
  if (code_start != (u8 *)0x0) {
    code_end = (u8 *)refs->entries[id].func_end;
    while (code_start < code_end) {
      BVar1 = find_instruction_with_mem_operand_ex
                        (code_start,code_end,(dasm_ctx_t *)&local_80,0x10b,(void *)0x0);
      if (BVar1 == 0) {
        code_start = code_start + 1;
      }
      else {
        if ((local_65 & 0x48) != 0x48) {
          if ((local_6f & 1) == 0) {
            if (mem_range_start == (void *)0x0) {
              return (u8 *)0x0;
            }
          }
          else {
            puVar2 = local_50;
            if ((local_64 & 0xff00ff00) == 0x5000000) {
              puVar2 = local_50 + (long)local_80 + local_78;
            }
            if ((mem_range_start <= puVar2) && (puVar2 <= (u8 *)((long)mem_range_end + -4))) {
              return puVar2;
            }
          }
        }
        code_start = code_start + local_78;
      }
    }
  }
  return (u8 *)0x0;
}

