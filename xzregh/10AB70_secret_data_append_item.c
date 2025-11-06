// /home/kali/xzre-ghidra/xzregh/10AB70_secret_data_append_item.c
// Function: secret_data_append_item @ 0x10AB70
// Calling convention: __stdcall
// Prototype: BOOL __stdcall secret_data_append_item(secret_data_shift_cursor_t shift_cursor, uint operation_index, uint shift_count, int index, u8 * code)
/*
 * AutoDoc: Generated from upstream sources.
 *
 * Source summary (xzre/xzre.h):
 *   @brief Calls @ref secret_data_append_singleton, if @p flags are non-zero
 *
 *   @param shift_cursor the initial shift index
 *   @param operation_index identification for this shift operation
 *   @param shift_count how many '1' bits to shift
 *   @param index must be non-zero in order for the operation to be executed
 *   @param code pointer to code that will be checked by the function, to "authorize" the data load
 *   @return BOOL TRUE if validation was successful and data was added, FALSE otherwise
 *
 * Upstream implementation excerpt (xzre/xzre_code/secret_data_append_item.c):
 *     BOOL secret_data_append_item(
 *     	secret_data_shift_cursor_t shift_cursor,
 *     	unsigned operation_index,
 *     	unsigned shift_count,
 *     	int index, u8 *code
 *     ){
 *     	return index && secret_data_append_singleton(
 *     		code, code,
 *     		shift_cursor, shift_count,
 *     		operation_index
 *     	);
 *     }
 */

BOOL secret_data_append_item
               (secret_data_shift_cursor_t shift_cursor,uint operation_index,uint shift_count,
               int index,u8 *code)

{
  BOOL BVar1;
  
  if (index != 0) {
    BVar1 = secret_data_append_singleton(code,code,shift_cursor,shift_count,operation_index);
    return BVar1;
  }
  return 0;
}

