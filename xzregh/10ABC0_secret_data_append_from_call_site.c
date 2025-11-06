// /home/kali/xzre-ghidra/xzregh/10ABC0_secret_data_append_from_call_site.c
// Function: secret_data_append_from_call_site @ 0x10ABC0
// Calling convention: __stdcall
// Prototype: BOOL __stdcall secret_data_append_from_call_site(secret_data_shift_cursor_t shift_cursor, uint shift_count, uint operation_index, BOOL bypass)
/*
 * AutoDoc: Generated from upstream sources.
 *
 * Source summary (xzre/xzre.h):
 *   @brief Shifts data in the secret data store, after validation of the call site,
 *   i.e. the caller of this function
 *   for more details, see @ref secret_data_append_singleton
 *
 *   @param shift_cursor the initial shift index
 *   @param shift_count number of '1' bits to shift
 *   @param operation_index index/id of shit shift operation
 *   @param bypass forces the result to be TRUE, evne if validation failed
 *   @return BOOL TRUE if validation was successful and data was added, FALSE otherwise
 */

BOOL secret_data_append_from_call_site
               (secret_data_shift_cursor_t shift_cursor,uint shift_count,uint operation_index,
               BOOL bypass)

{
  uint uVar1;
  u8 *unaff_retaddr;
  
  uVar1 = secret_data_append_singleton
                    ((u8 *)0x0,unaff_retaddr,shift_cursor,shift_count,operation_index);
  return uVar1 | bypass;
}

