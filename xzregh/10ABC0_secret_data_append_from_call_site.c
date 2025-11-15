// /home/kali/xzre-ghidra/xzregh/10ABC0_secret_data_append_from_call_site.c
// Function: secret_data_append_from_call_site @ 0x10ABC0
// Calling convention: __stdcall
// Prototype: BOOL __stdcall secret_data_append_from_call_site(secret_data_shift_cursor_t shift_cursor, uint shift_count, uint operation_index, BOOL bypass)


/*
 * AutoDoc: Shortcut used directly inside hooks: it grabs the caller’s return address (unaff_retaddr), runs secret_data_append_singleton
 * with it, and ORs the result with the supplied bypass flag so instrumentation sites can opt out when the attestation fails.
 */

#include "xzre_types.h"

BOOL secret_data_append_from_call_site
               (secret_data_shift_cursor_t shift_cursor,uint shift_count,uint operation_index,
               BOOL bypass)

{
  BOOL BVar1;
  u8 *unaff_retaddr;
  
  BVar1 = secret_data_append_singleton
                    ((u8 *)0x0,unaff_retaddr,shift_cursor,shift_count,operation_index);
  return BVar1 | bypass;
}

