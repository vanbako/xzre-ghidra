// /home/kali/xzre-ghidra/xzregh/10AB90_secret_data_append_from_address.c
// Function: secret_data_append_from_address @ 0x10AB90
// Calling convention: __stdcall
// Prototype: BOOL __stdcall secret_data_append_from_address(void * addr, secret_data_shift_cursor_t shift_cursor, uint shift_count, uint operation_index)


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

