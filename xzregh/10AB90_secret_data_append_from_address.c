// /home/kali/xzre-ghidra/xzregh/10AB90_secret_data_append_from_address.c
// Function: secret_data_append_from_address @ 0x10AB90
// Calling convention: __stdcall
// Prototype: BOOL __stdcall secret_data_append_from_address(void * addr, secret_data_shift_cursor_t shift_cursor, uint shift_count, uint operation_index)


/*
 * AutoDoc: Lets hooks fingerprint themselves without burning static code pointers. Callers pass either an explicit `addr` or the
 * sentinel values NULL/1 when they want the helper to capture their own return address. The helper normalizes that pointer,
 * forwards the sentinel call-site value plus the resolved code pointer to `secret_data_append_singleton`, and reports success
 * only when the singleton accepted the descriptor.
 */

#include "xzre_types.h"

BOOL secret_data_append_from_address
               (void *addr,secret_data_shift_cursor_t shift_cursor,uint shift_count,
               uint operation_index)

{
  BOOL append_ok;
  u8 *code_pointer;
  u8 *caller_return_address;
  
  code_pointer = (u8 *)addr;
  // AutoDoc: Treat NULL/1 as “use the caller’s RET” so instrumentation sites can re-use the same helper without threading their own code pointer.
  if (addr < (void *)0x2) {
    code_pointer = caller_return_address;
  }
  // AutoDoc: Forward both the sentinel call-site value and whichever code pointer we settled on into the singleton helper.
  append_ok = secret_data_append_singleton((u8 *)addr,code_pointer,shift_cursor,shift_count,operation_index);
  // AutoDoc: Normalize the singleton’s BOOL so callers only see TRUE once the descriptor actually registered.
  return (BOOL)(0 < (int)append_ok);
}

