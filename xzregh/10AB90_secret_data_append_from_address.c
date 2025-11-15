// /home/kali/xzre-ghidra/xzregh/10AB90_secret_data_append_from_address.c
// Function: secret_data_append_from_address @ 0x10AB90
// Calling convention: __stdcall
// Prototype: BOOL __stdcall secret_data_append_from_address(void * addr, secret_data_shift_cursor_t shift_cursor, uint shift_count, uint operation_index)


/*
 * AutoDoc: Lets hooks fingerprint themselves without a static code pointer. If addr is NULL/1 it substitutes the caller’s return address,
 * otherwise it uses the explicit address, and in either case it forwards both the call site and the resolved code pointer to
 * secret_data_append_singleton.
 */

#include "xzre_types.h"

BOOL secret_data_append_from_address
               (void *addr,secret_data_shift_cursor_t shift_cursor,uint shift_count,
               uint operation_index)

{
  BOOL BVar1;
  u8 *code_00;
  u8 *code;
  
  code_00 = (u8 *)addr;
  if (addr < (void *)0x2) {
    code_00 = code;
  }
  BVar1 = secret_data_append_singleton((u8 *)addr,code_00,shift_cursor,shift_count,operation_index);
  return (BOOL)(0 < (int)BVar1);
}

