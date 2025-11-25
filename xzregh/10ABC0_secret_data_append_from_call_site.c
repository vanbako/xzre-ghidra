// /home/kali/xzre-ghidra/xzregh/10ABC0_secret_data_append_from_call_site.c
// Function: secret_data_append_from_call_site @ 0x10ABC0
// Calling convention: __stdcall
// Prototype: BOOL __stdcall secret_data_append_from_call_site(secret_data_shift_cursor_t shift_cursor, uint shift_count, uint operation_index, BOOL bypass)


/*
 * AutoDoc: Convenience wrapper used directly inside hooks that only need to log their own call site. It copies Ghidra’s
 * `unaff_retaddr` pseudo-variable into the code pointer slot, forces a NULL `call_site` so the singleton walks from the next CALL,
 * and lets callers OR in a bypass flag when the attestation failure should not abort the enclosing logic.
 */

#include "xzre_types.h"

BOOL secret_data_append_from_call_site
               (secret_data_shift_cursor_t shift_cursor,uint shift_count,uint operation_index,
               BOOL bypass)

{
  BOOL append_ok;
  u8 *caller_return_address;
  
  // AutoDoc: Pass NULL for `call_site` so `secret_data_append_singleton` starts scanning after the caller; the RET address doubles as the code pointer.
  append_ok = secret_data_append_singleton
                    ((u8 *)0x0,caller_return_address,shift_cursor,shift_count,operation_index);
  // AutoDoc: Let instrumentation sites opt out when they already satisfied their policy (or the log slot) even if the append failed.
  return append_ok | bypass;
}

