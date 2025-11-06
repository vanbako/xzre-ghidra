// /home/kali/xzre-ghidra/xzregh/10AB90_secret_data_append_from_address.c
// Function: secret_data_append_from_address @ 0x10AB90
// Calling convention: __stdcall
// Prototype: BOOL __stdcall secret_data_append_from_address(void * addr, secret_data_shift_cursor_t shift_cursor, uint shift_count, uint operation_index)
/*
 * AutoDoc: Generated from upstream sources.
 *
 * Source summary (xzre/xzre.h):
 *   @brief calls @ref secret_data_append_singleton
 *   with either the given code address or the return address, if @p addr is <= 1
 *
 *   @param addr the code address to use for the verification. NULL to use the return address
 *   @param shift_cursor the initial shift index
 *   @param shift_count how many '1' bits to shift
 *   @param operation_index identification for this shift operation
 *   @return BOOL
 *
 * Upstream implementation excerpt (xzre/xzre_code/secret_data_append_from_address.c):
 *     BOOL secret_data_append_from_address(
 *     	void *addr,
 *     	secret_data_shift_cursor_t shift_cursor,
 *     	unsigned shift_count, unsigned operation_index
 *     ){
 *     	u8 *code = (u8 *)addr;
 *     	if((uintptr_t)addr <= 1){
 *     		code = (u8 *)__builtin_return_address(0);
 *     	}
 *     	return secret_data_append_singleton(
 *     		addr, code,
 *     		shift_cursor, shift_count,
 *     		operation_index
 *     	);
 *     }
 */

BOOL secret_data_append_from_address
               (void *addr,secret_data_shift_cursor_t shift_cursor,uint shift_count,
               uint operation_index)

{
  BOOL BVar1;
  u8 *code;
  u8 *code_1;
  
  code = (u8 *)addr;
  if (addr < (void *)0x2) {
    code = code_1;
  }
  BVar1 = secret_data_append_singleton((u8 *)addr,code,shift_cursor,shift_count,operation_index);
  return (BOOL)(0 < BVar1);
}

